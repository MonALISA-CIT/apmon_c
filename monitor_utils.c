/**
 * \file monitor_utils.c
 * This file contains the implementations of some functions used for 
 * obtaining monitoring information.
 */

/*
 * Copyright (C) 2006 California Institute of Technology
 *
 * Permission is hereby granted, free of charge, to use, copy and modify 
 * this software and its documentation (the "Software") for any
 * purpose, provided that existing copyright notices are retained in 
 * all copies and that this notice is included verbatim in any distributions
 * or substantial portions of the Software. 
 * This software is a part of the MonALISA framework (http://monalisa.caltech.edu).
 * Users of the Software are asked to feed back problems, benefits,
 * and/or suggestions about the software to the MonALISA Development Team
 * (MonALISA-CIT@cern.ch). Support for this software - fixing of bugs,
 * incorporation of new features - is done on a best effort basis. All bug
 * fixes and enhancements will be made available under the same terms and
 * conditions as the original software,

 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY DERIVATIVES THEREOF,
 * EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. THIS SOFTWARE IS
 * PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include "ApMon.h"
#include "monitor_utils.h"
#include "proc_utils.h"
#include "mon_constants.h"
#include "utils.h"


void apMon_sendJobInfo(ApMon *apm) {
  int i;

 /* the apMon_free() function calls sendJobInfo() from another thread and 
     we need mutual exclusion */
  pthread_mutex_lock(&apm -> mutexBack);

  if (apm -> nMonJobs == 0) {
    pthread_mutex_unlock(&apm -> mutexBack);
    logger(WARNING, "There are no jobs to be monitored, not sending job monitoring information...");
    return;
  }

  logger(INFO, "Sending job monitoring information...");
  /* apm -> lastJobInfoSend = (time_t)crtTime; */

  /* send monitoring information for all the jobs specified by the user */
  for (i = 0; i < apm -> nMonJobs; i++) 
    apMon_sendOneJobInfo(apm, apm -> monJobs[i]);

   pthread_mutex_unlock(&apm -> mutexBack);
}

int apMon_updateJobInfo(ApMon *apm, MonitoredJob job) {
  int needJobInfo, needDiskInfo;
  int jobExists = TRUE, ret;

  PsInfo jobInfo;
  JobDirInfo dirInfo;

  /**** runtime, CPU & memory usage information ****/ 
  needJobInfo = apm -> actJobMonitorParams[JOB_RUN_TIME] || 
    apm -> actJobMonitorParams[JOB_CPU_TIME] || apm -> actJobMonitorParams[JOB_CPU_USAGE] ||
    apm -> actJobMonitorParams[JOB_MEM_USAGE] || apm -> actJobMonitorParams[JOB_VIRTUALMEM] 
    || apm -> actJobMonitorParams[JOB_RSS] || apm -> actJobMonitorParams[JOB_OPEN_FILES];
  if (needJobInfo) {
    ret = apMon_readJobInfo(job.pid, &jobInfo);
    if (ret == RET_ERROR || ret == PROCUTILS_ERROR) {
      apm -> jobRetResults[JOB_RUN_TIME] = apm -> jobRetResults[JOB_CPU_TIME] = 
	apm -> jobRetResults[JOB_CPU_USAGE] = apm -> jobRetResults[JOB_MEM_USAGE] =
	apm -> jobRetResults[JOB_VIRTUALMEM] = apm -> jobRetResults[JOB_RSS] = ret;
      apm -> jobRetResults[JOB_OPEN_FILES] = ret;
    }
    if (ret == PROCUTILS_ERROR)
      jobExists = FALSE;
    apm -> currentJobVals[JOB_RUN_TIME] = jobInfo.etime;
    apm -> currentJobVals[JOB_CPU_TIME] = jobInfo.cputime; 
    apm -> currentJobVals[JOB_CPU_USAGE] = jobInfo.pcpu;
    apm -> currentJobVals[JOB_MEM_USAGE] = jobInfo.pmem; 
    apm -> currentJobVals[JOB_VIRTUALMEM] = jobInfo.vsz;
    apm -> currentJobVals[JOB_RSS] = jobInfo.rsz;

    if (jobInfo.open_fd < 0)
      apm -> jobRetResults[JOB_OPEN_FILES] = RET_ERROR;
    apm -> currentJobVals[JOB_OPEN_FILES] = jobInfo.open_fd;
  }

#ifdef linux
  /* if the monitored job has terminated, remove it */
  /* (this can only be tested on Linux for the moment) */
  if (!jobExists) {
    apMon_removeJobToMonitor(apm, job.pid);
    return RET_ERROR;
  }
#endif

  /* disk usage information */
  needDiskInfo = apm -> actJobMonitorParams[JOB_DISK_TOTAL] || 
    apm -> actJobMonitorParams[JOB_DISK_USED] || apm -> actJobMonitorParams[JOB_DISK_FREE] ||
    apm -> actJobMonitorParams[JOB_DISK_USAGE] || apm -> actJobMonitorParams[JOB_WORKDIR_SIZE];
  if (needDiskInfo) {
    ret = apMon_readJobDiskUsage(job, &dirInfo);
    if (ret == RET_ERROR) {
      apm -> jobRetResults[JOB_WORKDIR_SIZE] = apm -> jobRetResults[JOB_DISK_TOTAL] = 
	apm -> jobRetResults[JOB_DISK_USED] = apm -> jobRetResults[JOB_DISK_USAGE] =
	apm -> jobRetResults[JOB_DISK_FREE] = RET_ERROR;
      return RET_ERROR;
    }
    apm -> currentJobVals[JOB_WORKDIR_SIZE] = dirInfo.workdir_size;
    apm -> currentJobVals[JOB_DISK_TOTAL] = dirInfo.disk_total; 
    apm -> currentJobVals[JOB_DISK_USED] = dirInfo.disk_used;
    apm -> currentJobVals[JOB_DISK_USAGE] = dirInfo.disk_usage; 
    apm -> currentJobVals[JOB_DISK_FREE] = dirInfo.disk_free;
  }

  return RET_SUCCESS;
}
 
void apMon_sendOneJobInfo(ApMon *apm, MonitoredJob job) {
  int i;
  int nParams = 0;

  char **paramNames, **paramValues;
  int *valueTypes;

  valueTypes = (int *)malloc(apm -> nJobMonitorParams * sizeof(int));
  paramNames = (char **)malloc(apm -> nJobMonitorParams * sizeof(char *));
  paramValues = (char **)malloc(apm -> nJobMonitorParams * sizeof(char *));

  for (i = 0; i < apm -> nJobMonitorParams; i++) {
    apm -> jobRetResults[i] = RET_SUCCESS;
    apm -> currentJobVals[i] = 0;
  }

  apMon_updateJobInfo(apm, job);

  for (i = 0; i < apm -> nJobMonitorParams; i++) {
    if (apm -> actJobMonitorParams[i] && 
	apm -> jobRetResults[i] != RET_ERROR && apm -> jobRetResults[i] !=
	PROCUTILS_ERROR) {
     
      paramNames[nParams] = apm -> jobMonitorParams[i];
      paramValues[nParams] = (char *)&(apm -> currentJobVals[i]);
      valueTypes[nParams] = XDR_REAL64;
      nParams++;
    } 
    /* don't disable the parameter (maybe for another job it can be
	 obtained) */
      /*
	else
	if (autoDisableMonitoring)
	actJobMonitorParams[ind] = 0;
      */
  }

  if (nParams == 0) {
    free(paramNames); free(valueTypes);
    free(paramValues);
    return;
  }
 
  apMon_sendParameters(apm, job.clusterName, job.nodeName, nParams, 
		       paramNames, valueTypes, paramValues);
  free(paramNames);
  free(valueTypes);
  free(paramValues);
}


void apMon_updateSysInfo(ApMon *apm) {
  int needCPUInfo, needSwapPagesInfo, needLoadInfo, needMemInfo,
    needNetInfo, needUptime, needProcessesInfo, needNetstatInfo;
  int ret;
 
  /**** CPU usage information ****/ 
  needCPUInfo = apm -> actSysMonitorParams[SYS_CPU_USAGE] || 
    apm -> actSysMonitorParams[SYS_CPU_USR] || 
    apm -> actSysMonitorParams[SYS_CPU_SYS] ||
    apm -> actSysMonitorParams[SYS_CPU_NICE] || 
    apm -> actSysMonitorParams[SYS_CPU_IDLE];
  if (needCPUInfo) {
    ret = procutils_updateCPUUsage(apm);
    if (ret == PROCUTILS_ERROR) {
      /* "permanent" error (the parameters could not be obtained) */
      apm -> sysRetResults[SYS_CPU_USAGE] = apm -> sysRetResults[SYS_CPU_SYS] =
	apm -> sysRetResults[SYS_CPU_USR] = apm -> sysRetResults[SYS_CPU_NICE] =
	apm -> sysRetResults[SYS_CPU_USAGE] = PROCUTILS_ERROR;
    }
    if (ret == RET_ERROR) {
      /* temporary error (next time we might be able to get the paramerers) */
      apm -> sysRetResults[SYS_CPU_USAGE] = apm -> sysRetResults[SYS_CPU_SYS] = 
	apm -> sysRetResults[SYS_CPU_USR] = apm -> sysRetResults[SYS_CPU_NICE] =
	apm -> sysRetResults[SYS_CPU_USAGE] = RET_ERROR;
    }
  }

  needSwapPagesInfo = apm -> actSysMonitorParams[SYS_PAGES_IN] || 
    apm -> actSysMonitorParams[SYS_PAGES_OUT] || 
    apm -> actSysMonitorParams[SYS_SWAP_IN] ||
    apm -> actSysMonitorParams[SYS_SWAP_OUT];

  if (needSwapPagesInfo) {
    ret = procutils_updateSwapPages(apm);
    if (ret == PROCUTILS_ERROR) {
      /* "permanent" error (the parameters could not be obtained) */
      apm -> sysRetResults[SYS_PAGES_IN] = apm -> sysRetResults[SYS_PAGES_OUT] = 
      apm -> sysRetResults[SYS_SWAP_OUT] = apm -> sysRetResults[SYS_SWAP_IN] 
	= PROCUTILS_ERROR;
    } 
    if (ret == RET_ERROR) {
      /* temporary error (next time we might be able to get the paramerers) */
      apm -> sysRetResults[SYS_PAGES_IN] = apm -> sysRetResults[SYS_PAGES_OUT] = 
	apm -> sysRetResults[SYS_SWAP_IN] = apm -> sysRetResults[SYS_SWAP_OUT] 
	= RET_ERROR;
    }
  }

  needLoadInfo = apm -> actSysMonitorParams[SYS_LOAD1] || 
    apm -> actSysMonitorParams[SYS_LOAD5] || 
    apm -> actSysMonitorParams[SYS_LOAD15] ||
    apm -> actSysMonitorParams[SYS_PROCESSES];
  if (needLoadInfo) {
    ret = procutils_updateLoad(apm);
    if (ret == PROCUTILS_ERROR) {
      /* "permanent" error (the parameters could not be obtained) */
      apm -> sysRetResults[SYS_LOAD1] = apm -> sysRetResults[SYS_LOAD5] = 
	apm -> sysRetResults[SYS_LOAD15] = 
	apm -> sysRetResults[SYS_PROCESSES] = PROCUTILS_ERROR;
    }
  }

  /**** get statistics about the current processes ****/
  needProcessesInfo = apm -> actSysMonitorParams[SYS_PROCESSES];
  if (needProcessesInfo) {
    ret = procutils_getProcesses(&(apm -> currentSysVals[SYS_PROCESSES]), 
			      apm -> currentProcessStates);
    if (ret == RET_ERROR) {
      apm -> sysRetResults[SYS_PROCESSES] = RET_ERROR;
    }
  }

  /**** get the amount of memory currently in use ****/
  needMemInfo = apm -> actSysMonitorParams[SYS_MEM_USED] || 
    apm -> actSysMonitorParams[SYS_MEM_FREE] || 
    apm -> actSysMonitorParams[SYS_SWAP_USED] ||
    apm -> actSysMonitorParams[SYS_SWAP_FREE] || 
    apm -> actSysMonitorParams[SYS_MEM_USAGE] ||
    apm -> actSysMonitorParams[SYS_SWAP_USAGE];

  if (needMemInfo) {
    ret = procutils_updateMemUsed(apm);
    if (ret == PROCUTILS_ERROR) {  
      apm -> sysRetResults[SYS_MEM_USED] = apm -> sysRetResults[SYS_MEM_FREE] = 
	apm -> sysRetResults[SYS_SWAP_USED] = apm -> sysRetResults[SYS_SWAP_FREE] = 
	apm -> sysRetResults[SYS_MEM_USAGE] = 
	apm -> sysRetResults[SYS_SWAP_USAGE] = 	PROCUTILS_ERROR;
    }
  }

  
  /**** network monitoring information ****/
  needNetInfo = apm -> actSysMonitorParams[SYS_NET_IN] || 
    apm -> actSysMonitorParams[SYS_NET_OUT] || 
    apm -> actSysMonitorParams[SYS_NET_ERRS];
  if (needNetInfo && apm -> nInterfaces > 0) {
    ret = procutils_getNetInfo(apm);
    if (ret == PROCUTILS_ERROR) {
      apm -> sysRetResults[SYS_NET_IN] = apm -> sysRetResults[SYS_NET_OUT] = 
	apm -> sysRetResults[SYS_NET_ERRS] = PROCUTILS_ERROR;     
    }
    if (ret == RUNTIME_ERROR) {
      apm -> sysRetResults[SYS_NET_IN] = apm -> sysRetResults[SYS_NET_OUT] = 
	apm -> sysRetResults[SYS_NET_ERRS] = RET_ERROR; 
    }
  }

  needNetstatInfo = apm -> actSysMonitorParams[SYS_NET_SOCKETS] || 
    apm -> actSysMonitorParams[SYS_NET_TCP_DETAILS];
  if (needNetstatInfo) {
    ret = procutils_getNetstatInfo(apm);
    if (ret == RET_ERROR) {
      apm -> sysRetResults[SYS_NET_SOCKETS] = 
	apm -> sysRetResults[SYS_NET_TCP_DETAILS] = RET_ERROR; 
    }
  }

  needUptime = apm -> actSysMonitorParams[SYS_UPTIME];
  if (needUptime) {
    apm -> currentSysVals[SYS_UPTIME] = procutils_getUpTime();
    if (apm -> currentSysVals[SYS_UPTIME] == PROCUTILS_ERROR) {
      apm -> sysRetResults[SYS_UPTIME] = PROCUTILS_ERROR;
    } 
  }


}

void apMon_sendSysInfo(ApMon *apm) {
  int nParams = 0, maxNParams;
  int i;
  long crtTime;

  char **paramNames, **paramValues;
  int *valueTypes;

  crtTime = time(NULL);
  logger(INFO, " Sending system monitoring information...");

  /* make some initializations only the first time this
     function is called */
  if (apm -> sysInfo_first) {
    for (i = 0; i < apm -> nInterfaces; i++) {
      apm -> lastBytesSent[i] = apm -> lastBytesReceived[i] = 0.0;
      apm -> lastNetErrs[i] = 0.0;
    }
    apm -> sysInfo_first = FALSE;
  }

  /* the maximum number of parameters that can be included in a datagram */
  /* (the last three terms are for: parameters corresponding to each possible
     state of the processes, parameters corresponding to the types of open 
     sockets, parameters corresponding to each possible state of the TCP
     sockets.) */
  maxNParams = apm -> nSysMonitorParams + (2 * apm -> nInterfaces - 1) +
    15 + 4 + N_TCP_STATES;

  valueTypes = (int *)malloc(maxNParams * sizeof(int));
  paramNames = (char **)malloc(maxNParams * sizeof(char *));
  paramValues = (char **)malloc(maxNParams * sizeof(char *));

  for (i = 0; i < apm -> nSysMonitorParams; i++) {
    if (apm -> actSysMonitorParams[i] > 0) /* if the parameter is enabled */
      apm -> sysRetResults[i] = RET_SUCCESS;
    else /* mark it with RET_ERROR so that it will be not included in the
	    datagram */
      apm -> sysRetResults[i] = RET_ERROR;
  }

  apMon_updateSysInfo(apm);

  for (i = 0; i < apm -> nSysMonitorParams; i++) {
    if (i == SYS_NET_IN || i == SYS_NET_OUT || i == SYS_NET_ERRS ||
	i == SYS_NET_SOCKETS || i == SYS_NET_TCP_DETAILS || i == SYS_PROCESSES)
      continue;

    if (apm -> sysRetResults[i] == PROCUTILS_ERROR) {
      /* could not read the requested information from /proc, disable this
	 parameter */
      if (apm -> autoDisableMonitoring)
	apm -> actSysMonitorParams[i] = 0;
    } else if (apm -> sysRetResults[i] != RET_ERROR) {
      /* the parameter is enabled and there were no errors obtaining it */
      paramNames[nParams] = strdup(apm -> sysMonitorParams[i]);
      paramValues[nParams] = (char *)&(apm -> currentSysVals[i]);
      valueTypes[nParams] = XDR_REAL64;
      nParams++;
    } 
  }

  if (apm -> actSysMonitorParams[SYS_NET_IN] == 1) {
    if (apm -> sysRetResults[SYS_NET_IN] == PROCUTILS_ERROR) {
      if (apm -> autoDisableMonitoring)
	apm -> actSysMonitorParams[SYS_NET_IN] = 0;
    } else if (apm -> sysRetResults[SYS_NET_IN] != RET_ERROR) {
      for (i = 0; i < apm -> nInterfaces; i++) { 
	paramNames[nParams] =  (char *)malloc(20 * sizeof(char));
	strcpy(paramNames[nParams], apm -> interfaceNames[i]);
	strcat(paramNames[nParams], "_in");
	paramValues[nParams] = (char *)&(apm -> currentNetIn[i]);
	valueTypes[nParams] = XDR_REAL64;
	nParams++;
      }
    }
  }

  if (apm -> actSysMonitorParams[SYS_NET_OUT] == 1) {
    if (apm -> sysRetResults[SYS_NET_IN] == PROCUTILS_ERROR) {
      if (apm -> autoDisableMonitoring)
	apm -> actSysMonitorParams[SYS_NET_OUT] = 0;
    } else  if (apm -> sysRetResults[SYS_NET_OUT] != RET_ERROR) {
      for (i = 0; i < apm -> nInterfaces; i++) { 
	paramNames[nParams] =  (char *)malloc(20 * sizeof(char));
	strcpy(paramNames[nParams], apm -> interfaceNames[i]);
	strcat(paramNames[nParams], "_out");
	paramValues[nParams] = (char *)&(apm -> currentNetOut[i]);
	valueTypes[nParams] = XDR_REAL64;
	nParams++;
      }
    }
  }

  if (apm -> actSysMonitorParams[SYS_NET_ERRS] == 1) {
    if (apm -> sysRetResults[SYS_NET_ERRS] == PROCUTILS_ERROR) {
      if (apm -> autoDisableMonitoring)
	apm -> actSysMonitorParams[SYS_NET_ERRS] = 0;
    } else  if (apm -> sysRetResults[SYS_NET_ERRS] != RET_ERROR) {
      for (i = 0; i < apm -> nInterfaces; i++) { 
	paramNames[nParams] =  (char *)malloc(20 * sizeof(char));
	strcpy(paramNames[nParams], apm -> interfaceNames[i]);
	strcat(paramNames[nParams], "_errs");
	paramValues[nParams] = (char *)&(apm -> currentNetErrs[i]);
	valueTypes[nParams] = XDR_REAL64;
	nParams++;
      }
    }
  }

  if (apm -> actSysMonitorParams[SYS_NET_SOCKETS] == 1) {
    if (apm -> sysRetResults[SYS_NET_SOCKETS] != RET_ERROR) {
      char *socket_types[] = {"tcp", "udp", "icm", "unix"};
      for (i = 0; i < 4; i++) { 
	paramNames[nParams] =  (char *)malloc(30 * sizeof(char));
	sprintf(paramNames[nParams], "sockets_%s", socket_types[i]);
	paramValues[nParams] = (char *)&(apm -> currentNSockets[i]);
	valueTypes[nParams] = XDR_REAL64;
	nParams++;
      }
    }
  }

  if (apm -> actSysMonitorParams[SYS_NET_TCP_DETAILS] == 1) {
    if (apm -> sysRetResults[SYS_NET_TCP_DETAILS] != RET_ERROR) {
      for (i = 0; i < N_TCP_STATES; i++) { 
	paramNames[nParams] =  (char *)malloc(30 * sizeof(char));
	sprintf(paramNames[nParams], "sockets_tcp_%s", 
		apm -> socketStatesMapTCP[i]);
	paramValues[nParams] = (char *)&(apm -> currentSocketsTCP[i]);
	valueTypes[nParams] = XDR_REAL64;
	nParams++;
      }
    }
  }
  
  apMon_sendParameters(apm, apm -> sysMonCluster, apm -> sysMonNode, nParams, 
		       paramNames, valueTypes, paramValues);

  apm -> lastSysInfoSend = crtTime;


 if (apm -> sysRetResults[SYS_NET_IN] == RET_SUCCESS) {
    free(apm -> currentNetIn);
    free(apm -> currentNetOut);
    free(apm -> currentNetErrs);
  }

  for (i = 0; i < nParams; i++)
    free(paramNames[i]);
  free(paramNames);
  free(valueTypes);
  free(paramValues);
}

void apMon_updateGeneralInfo(ApMon *apm) {
  int ret; 

  strcpy(apm -> cpuVendor, ""); strcpy(apm -> cpuFamily, "");
  strcpy(apm -> cpuModel, ""); strcpy(apm -> cpuModelName, "");

  if (apm -> actGenMonitorParams[GEN_CPU_MHZ] == 1 || 
      apm -> actGenMonitorParams[GEN_BOGOMIPS] == 1 || 
      apm -> actGenMonitorParams[GEN_CPU_VENDOR_ID] == 1 ||
      apm -> actGenMonitorParams[GEN_CPU_FAMILY] == 1 || 
      apm -> actGenMonitorParams[GEN_CPU_MODEL] == 1 ||
      apm -> actGenMonitorParams[GEN_CPU_MODEL_NAME] == 1) {

      ret = procutils_getCPUInfo(apm);
      if (ret == PROCUTILS_ERROR) {
	apm -> genRetResults[GEN_CPU_MHZ] = 
	  apm -> genRetResults[GEN_BOGOMIPS] = PROCUTILS_ERROR;
      }
  }

  if (apm -> actGenMonitorParams[GEN_TOTAL_MEM] == 1 || 
      apm -> actGenMonitorParams[GEN_TOTAL_SWAP] == 1) {

    ret = procutils_getSysMem(&(apm -> currentGenVals[GEN_TOTAL_MEM]), 
			   &(apm -> currentGenVals[GEN_TOTAL_SWAP]));
    if (ret == PROCUTILS_ERROR) {
      apm -> genRetResults[GEN_TOTAL_MEM] = 
	apm -> genRetResults[GEN_TOTAL_SWAP] = PROCUTILS_ERROR;
    }
  }
  
  apm -> currentGenVals[GEN_NO_CPUS] = apm -> numCPUs;
}

void apMon_sendGeneralInfo(ApMon *apm) {
  int nParams, ind, maxNParams, i;
  char tmp_s[50];
  
  char **paramNames, **paramValues;
  int *valueTypes;

  logger(INFO, "Sending general monitoring information...");
  
  maxNParams = apm -> nGenMonitorParams + apm -> numIPs;
  valueTypes = (int *)malloc(maxNParams * sizeof(int));
  paramNames = (char **)malloc(maxNParams * sizeof(char *));
  paramValues = (char **)malloc(maxNParams * sizeof(char *));
  
  nParams = 0;

  apMon_updateGeneralInfo(apm);

  if (apm -> actGenMonitorParams[GEN_HOSTNAME]) {
    paramNames[nParams] = strdup(apm -> genMonitorParams[GEN_HOSTNAME]);
    valueTypes[nParams] = XDR_STRING;
    paramValues[nParams] = apm -> myHostname;
    nParams++;
  }

  if (apm -> actGenMonitorParams[GEN_IP]) {
    for (i = 0; i < apm -> numIPs; i++) {
      strcpy(tmp_s, "ip_");
      strcat(tmp_s, apm -> interfaceNames[i]);
      paramNames[nParams] = strdup(tmp_s);
      valueTypes[nParams] = XDR_STRING;
      paramValues[nParams] = apm -> allMyIPs[i];
      nParams++;
    }
  }

  if (apm -> actGenMonitorParams[GEN_CPU_VENDOR_ID] && 
      strlen(apm -> cpuVendor) != 0) {
    paramNames[nParams] = strdup(apm -> genMonitorParams[GEN_CPU_VENDOR_ID]);
    valueTypes[nParams] = XDR_STRING;
    paramValues[nParams] = apm -> cpuVendor;
    nParams++;
  }

  if (apm -> actGenMonitorParams[GEN_CPU_FAMILY] && 
      strlen(apm -> cpuFamily) != 0) {
    paramNames[nParams] = strdup(apm -> genMonitorParams[GEN_CPU_FAMILY]);
    valueTypes[nParams] = XDR_STRING;
    paramValues[nParams] = apm -> cpuFamily;
    nParams++;
  }

  if (apm -> actGenMonitorParams[GEN_CPU_MODEL] && strlen(apm -> cpuModel) != 0) {
    paramNames[nParams] = strdup(apm -> genMonitorParams[GEN_CPU_MODEL]);
    valueTypes[nParams] = XDR_STRING;
    paramValues[nParams] = apm -> cpuModel;
    nParams++;
  }
  
  if (apm -> actGenMonitorParams[GEN_CPU_MODEL_NAME] && 
      strlen(apm -> cpuModelName) != 0) {
    paramNames[nParams] = strdup(apm -> genMonitorParams[GEN_CPU_MODEL_NAME]);
    valueTypes[nParams] = XDR_STRING;
    paramValues[nParams] = apm -> cpuModelName;
    nParams++;
  }

  for (i = 0; i < apm -> nGenMonitorParams; i++) {
    if (apm -> actGenMonitorParams[i] != 1 || i == GEN_IP || i == GEN_HOSTNAME ||
	i == GEN_CPU_VENDOR_ID || i == GEN_CPU_FAMILY || i == GEN_CPU_MODEL
	|| i == GEN_CPU_MODEL_NAME)
      continue;

    if (apm -> genRetResults[i] == PROCUTILS_ERROR) {
      /* could not read the requested information from /proc, disable this
	 parameter */
      if (apm -> autoDisableMonitoring)
	apm -> actGenMonitorParams[ind] = 0;
    } else if (apm -> genRetResults[i] != RET_ERROR) {
      paramNames[nParams] = strdup(apm -> genMonitorParams[i]);
      paramValues[nParams] = (char *)&(apm -> currentGenVals[i]);
      valueTypes[nParams] = XDR_REAL64;
      nParams++;
    } 
  }

  apMon_sendParameters(apm, apm -> sysMonCluster, apm -> sysMonNode, nParams, 
		       paramNames, valueTypes, paramValues);

  for (i = 0; i < nParams; i++)
    free(paramNames[i]);
  free(paramNames);
  free(valueTypes);
  free(paramValues);
}

void apMon_initMonitoring(MonitorConf *mconf) {
  int i;

  mconf -> autoDisableMonitoring = TRUE;
  mconf -> sysMonitoring = FALSE;
  mconf -> jobMonitoring = FALSE;
  mconf -> genMonitoring = FALSE;
  mconf -> confCheck = FALSE;

  mconf -> recheckInterval = RECHECK_INTERVAL;
  mconf -> crtRecheckInterval = RECHECK_INTERVAL;
  mconf -> jobMonitorInterval = JOB_MONITOR_INTERVAL;
  mconf -> sysMonitorInterval = SYS_MONITOR_INTERVAL;


  mconf -> nSysMonitorParams = initSysParams(mconf -> sysMonitorParams);

  mconf -> nGenMonitorParams = initGenParams(mconf -> genMonitorParams);

  mconf -> nJobMonitorParams = initJobParams(mconf -> jobMonitorParams);


  for (i = 0; i < mconf -> nSysMonitorParams; i++) {
    mconf -> actSysMonitorParams[i] = 1;
  }

  for (i = 0; i < mconf -> nGenMonitorParams; i++) {
    mconf -> actGenMonitorParams[i] = 1;
  }

  for (i = 0; i < mconf -> nJobMonitorParams; i++) {
    mconf -> actJobMonitorParams[i] = 1;
  }

  mconf -> maxMsgRate = MAX_MSG_RATE;
}

void apMon_copyParamNames(ApMon *apm, MonitorConf mconf) {
  int i;

  apm -> nSysMonitorParams = mconf.nSysMonitorParams;
  for (i = 0; i < mconf.nSysMonitorParams; i++)
    apm -> sysMonitorParams[i] = strdup(mconf.sysMonitorParams[i]);

  apm -> nGenMonitorParams = mconf.nGenMonitorParams;
  for (i = 0; i < mconf.nGenMonitorParams; i++)
    apm -> genMonitorParams[i] = strdup(mconf.genMonitorParams[i]);

  apm -> nJobMonitorParams = mconf.nJobMonitorParams;
  for (i = 0; i < mconf.nJobMonitorParams; i++)
    apm -> jobMonitorParams[i] = strdup(mconf.jobMonitorParams[i]);
}

void apMon_copyMonSettings(ApMon *apm, MonitorConf mconf) {
  int i;

  apm -> autoDisableMonitoring = mconf.autoDisableMonitoring;
  apm -> sysMonitoring = mconf.sysMonitoring;
  apm -> jobMonitoring = mconf.jobMonitoring;
  apm -> genMonitoring = mconf.genMonitoring;
  apm -> confCheck = mconf.confCheck;

  apm -> recheckInterval = mconf.recheckInterval;
  apm -> crtRecheckInterval = mconf.crtRecheckInterval;
  apm -> jobMonitorInterval = mconf.jobMonitorInterval;
  apm -> sysMonitorInterval = mconf.sysMonitorInterval;

  for (i = 0; i < mconf.nSysMonitorParams; i++)
    apm -> actSysMonitorParams[i] = mconf.actSysMonitorParams[i];

  for (i = 0; i < mconf.nGenMonitorParams; i++)
    apm -> actGenMonitorParams[i] = mconf.actGenMonitorParams[i];

  for (i = 0; i < mconf.nJobMonitorParams; i++)
    apm -> actJobMonitorParams[i] = mconf.actJobMonitorParams[i];

  apm -> maxMsgRate = mconf.maxMsgRate;
}
  
void apMon_parseXApMonLine(MonitorConf *mconf, char *line) {
  int flag, found;
  int ind;
  char tmp[MAX_STRING_LEN];
  char *param, *value, *tmp2;
  char buf[MAX_STRING_LEN], logmsg[100];
  char *pbuf = buf;
  char *sep = " =";

  strcpy(tmp, line);
  tmp2 = tmp + strlen("xApMon_");

  param = strtok_r(tmp2, sep, &pbuf);
  value = strtok_r(NULL, sep, &pbuf);

  if (strcmp(value, "on") == 0)
    flag = TRUE;
  else /* if it is not an on/off paramenter the value of flag doesn't matter */
    flag = FALSE;
  
  /*  pthread_mutex_lock(&apm -> mutexBack); */

  found = FALSE;
  if (strcmp(param, "job_monitoring") == 0) {
    mconf -> jobMonitoring = flag; found = TRUE;
  }
  if (strcmp(param, "sys_monitoring") == 0) {
    mconf -> sysMonitoring = flag; found = TRUE;
  }
  if (strcmp(param, "job_interval") == 0) {
    mconf -> jobMonitorInterval = atol(value); found = TRUE;
  }
  if (strcmp(param, "sys_interval") == 0) {
    mconf -> sysMonitorInterval = atol(value); found = TRUE;
  }
  if (strcmp(param, "general_info") == 0) {
    mconf -> genMonitoring = flag; found = TRUE;
  }
  if (strcmp(param, "conf_recheck") == 0) {
    mconf -> confCheck = flag; found = TRUE;
  }
  if (strcmp(param, "recheck_interval") == 0) {
    mconf -> recheckInterval = mconf -> crtRecheckInterval = atol(value); 
    found = TRUE;
  }
  if (strcmp(param, "auto_disable") == 0) {
    mconf -> autoDisableMonitoring = flag;
    found = TRUE;
  }
  if (strcmp(param, "maxMsgRate") == 0) {
    mconf -> maxMsgRate = atoi(value);
    found = TRUE;
  }


  if (found) {
    /* pthread_mutex_unlock(&apm -> mutexBack); */
    return;
  }

  if (strstr(param, "sys_") == param) {
    ind = getVectIndex(param + strlen("sys_"), mconf -> sysMonitorParams, 
		       mconf -> nSysMonitorParams);
    if (ind < 0) {
      /* pthread_mutex_unlock(&apm -> mutexBack); */
      sprintf(logmsg, "Invalid parameter name in the configuration file: %s",
	    param);
      logger(WARNING, logmsg);
      return;
    }
    found = TRUE;
    mconf -> actSysMonitorParams[ind] = (int)flag;
  }

  if (strstr(param, "job_") == param) {
    ind = getVectIndex(param + strlen("job_"), mconf -> jobMonitorParams, 
		       mconf -> nJobMonitorParams);
    
    if (ind < 0) {
      /* pthread_mutex_unlock(&apm -> mutexBack); */
      sprintf(logmsg, "Invalid parameter name in the configuration file: %s",
	    param);
      logger(WARNING, logmsg);
      return;
    }
    found = TRUE;
    mconf -> actJobMonitorParams[ind] = (int)flag;
  }

  if (!found) {
    ind = getVectIndex(param, mconf -> genMonitorParams, 
		       mconf -> nGenMonitorParams);
    if (ind < 0) {
      /* pthread_mutex_unlock(&apm -> mutexBack); */
      sprintf(logmsg, "Invalid parameter name in the configuration file: %s",
	      param);
      logger(WARNING, logmsg);
      return;
    } else {
      found = TRUE;
      mconf -> actGenMonitorParams[ind] = (int)flag;
    }
  }

  if (!found) {
    sprintf(logmsg, "Invalid parameter name in the configuration file: %s",
	    param);
    logger(WARNING, logmsg);
    return;
    /* pthread_mutex_unlock(&apm -> mutexBack); */
  }
}

long *getChildren(long pid, int *nChildren) {
  FILE *pf;
  long *pids, *ppids, *children;
  int nProcesses, processFound;
  int i, j, status;
  pid_t cpid;
  char *argv[4], cmd[200];
  long mypid = getpid();
  char logmsg[100];
  char children_f[50], np_f[50];

  /* generate the names of the temporary files in which we have the output
     of some commands */
  sprintf(children_f, "/tmp/out_children%ld", mypid);
  sprintf(np_f, "/tmp/out_np%ld", mypid);

  switch (cpid = fork()) {
  case -1:
    logger(WARNING, "Unable to fork(). The number of child processes could not be determined\n");
    return NULL;
  case 0:
    argv[0] = "/bin/sh"; argv[1] =  "-c";
    sprintf(cmd, "ps --no-headers -eo ppid,pid > %s && wc -l %s > %s",
	    children_f, children_f, np_f);
    argv[2] = cmd;
    /*
    argv[2] = "ps --no-headers -eo ppid,pid > /tmp/out_children.txt && wc -l /tmp/out_children.txt > /tmp/out_np.txt";
    */
    argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      sprintf(logmsg, "The number of sub-processes for %ld could not be determined", pid);
      unlink(children_f); unlink(np_f);
      logger(WARNING, logmsg);
      return NULL; 
    }
  }

  /* find the number of processes */
  pf = fopen(np_f, "rt");
  if (pf == NULL) {
    unlink(children_f); unlink(np_f);
    sprintf(logmsg, "The number of sub-processes for %ld could not be determined", pid);
    logger(WARNING, logmsg);
    return NULL;
  }
  else {
    fscanf(pf, "%d", &nProcesses);
    fclose(pf);   
  }
  unlink(np_f);

  pids = (long *)malloc(nProcesses * sizeof(long)); 
  ppids = (long *)malloc(nProcesses * sizeof(long)); 
  /* estimated maximum size for the returned vector; it will be realloc'ed */
  children = (long *)malloc(nProcesses * sizeof(long));

  pf = fopen(children_f, "rt");
  if (pf == NULL) {
    sprintf(logmsg, "The sub-processes for %ld could not be determined", pid);
    logger(WARNING, logmsg);
    return NULL;
  } 
 
  /* scan the output of the ps command and find the children of the process */
  children[0] = pid; *nChildren = 1; 
  processFound = FALSE;
  for (i = 0; i < nProcesses; i++) {
    fscanf(pf, "%ld %ld", &ppids[i], &pids[i]);
    if (pids[i] == children[0])
      processFound = TRUE;
    if (ppids[i] == children[0]) {
      children[*nChildren] = pids[i];
      (*nChildren)++;
    }
  }
  fclose(pf);
  unlink(children_f);

  if (processFound == FALSE) {
    free(pids); free(ppids); free(children);
    nChildren = 0;
    sprintf(logmsg, "The process %ld does not exist", pid);
    logger(WARNING, logmsg);
    return NULL;
  } 

  /* find the PIDs of all the descendant processes */
  i = 1;
  while (i < *nChildren) {
    /* find the children of the i-th child */ 
    for (j = 0; j < nProcesses; j++) {
      if (ppids[j] == children[i]) {
	children[*nChildren] = pids[j];
	(*nChildren)++;
      }
    }
    i++;
  }

  /*
  printf("### children: ");
  for (i = 0; i < *nChildren; i++)
    printf("%ld ", children[i]);
  printf("\n");
  */
  free(pids); free(ppids);
  children = (long *)realloc(children, (*nChildren) * sizeof(long));
  return children;
}

int apMon_readJobInfo(long pid, PsInfo *info) {
  long *children;
  FILE *fp;
  int i, nChildren, status, ch, ret, open_fd;
  char *cmd , *mem_cmd_s, *argv[4], *ret_s;
  char pid_s[10];
  char cmdName[100], etime_s[20], cputime_s[20], buf[MAX_STRING_LEN], buf2[100];
  double rsz, vsz;
  double etime, cputime;
  double pcpu, pmem;
  /* this list contains strings of the form "rsz_vsz_command" for every pid;
     it is used to avoid adding several times processes that have multiple 
     threads and appear in ps as sepparate processes, occupying exactly the 
     same amount of memory and having the same command name. For every line 
     from the output of the ps command we verify if the rsz_vsz_command 
     combination is already in the list.
  */
  char **mem_cmd_list;
  int listSize;
  long cpid, crt_pid;
  int maxCmdLen = 5 * MAX_STRING_LEN;
  char logmsg[100];
  long mypid = getpid();
  char ps_f[50];

  /* generate a name for the temporary file which holds the output of the 
     ps command */
  sprintf(ps_f, "/tmp/out_ps%ld", mypid);

  /* get the list of the process' descendants */
  children = getChildren(pid, &nChildren);
  if (children == NULL)
    return PROCUTILS_ERROR;

  cmd = (char *)malloc (5 * maxCmdLen * sizeof(char));
  /* issue the "ps" command to obtain information on all the descendants */
  strcpy(cmd, "ps --no-headers --pid ");
  for (i = 0; i < nChildren - 1; i++) {
    sprintf(pid_s, "%ld,", children[i]);
    if (strlen(cmd) + strlen(pid_s) +1 >= MAX_STRING_LEN) {
      free(cmd);
      sprintf(logmsg, "Job %ld has too many sub-processes to be monitored",
	      pid);
      logger(WARNING, logmsg);
      return RET_ERROR;
    }
    strcat(cmd, pid_s);
  }

  /* the last part of the command */
  sprintf(pid_s, "%ld", children[nChildren - 1]);
  sprintf(cmdName, " -o pid,etime,time,%%cpu,%%mem,rsz,vsz,comm > %s", ps_f);
  if (strlen(cmd) + strlen(pid_s) + strlen(cmdName) > maxCmdLen) {
    free(cmd);
    sprintf(logmsg, "Job %ld has too many sub-processes to be monitored",
	      pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }
  strcat(cmd, pid_s);
  strcat(cmd, cmdName);

  switch (cpid = fork()) {
  case -1:
    free(cmd);
    sprintf(logmsg, "Unable to fork(). The job information could not be determined for %ld", pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  case 0:
    argv[0] = "/bin/sh"; argv[1] = "-c";
    argv[2] = cmd; argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      free(cmd);
      sprintf(logmsg, "The job information for %ld could not be determined", pid);
      logger(WARNING, logmsg);
      return RET_ERROR; 
    }
  }

  free(cmd);
  fp = fopen(ps_f, "rt");
  if (fp == NULL) {
    sprintf(logmsg, "Error opening the ps output file for process %ld", pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }

  /* parse the output file */
  info -> etime = info -> cputime = 0;
  info -> pcpu = info -> pmem = 0;
  info -> rsz = info -> vsz = 0;
  info -> open_fd = 0;

  mem_cmd_list = (char **)malloc(nChildren * sizeof(char *));
  listSize = 0;
  cmdName[0] = 0;

  while (1) {
    ret_s = fgets(buf, MAX_STRING_LEN, fp);
    if (ret_s == NULL) 
      break;
    buf[MAX_STRING_LEN - 1] = 0;

    /* if the line was too long and fgets hasn't read it entirely, */
    /* keep only the first 512 chars from the line */
    ch = fgetc(fp); /* see if we are at the end of the file */
    ungetc(ch, fp);
    if (buf[strlen(buf) - 1] != 10 && ch != EOF) { 
      while (1) {
	char *sret = fgets(buf2, MAX_STRING_LEN, fp);
	if (sret == NULL || buf2[strlen(buf2) - 1] == 10)
	  break;
      }
    }

    ret = sscanf(buf, "%ld %s %s %lf %lf %lf %lf %s", &crt_pid, etime_s, 
		 cputime_s, &pcpu, &pmem, &rsz, &vsz, cmdName);
    if (ret != 8) {
      fclose(fp);
      unlink(ps_f);
      free(children);
      for (i = 0; i < listSize; i++) {
	free(mem_cmd_list[i]);
      }
      free(mem_cmd_list);
      logger(WARNING, "[ apMon_readJobInfo() ] Error parsing the output of the ps command");
      return RET_ERROR;
    }

    /* etime is the maximum of the elapsed times for the subprocesses */
    etime = apMon_parsePSTime(etime_s);
    info -> etime = (info -> etime > etime) ? info -> etime : etime;

    /* cputime is the sum of the cpu times for the subprocesses */
    cputime = apMon_parsePSTime(cputime_s);
    info -> cputime += cputime;

    info -> pcpu += pcpu;

    /* get the number of opened file descriptors */
    open_fd = procutils_countOpenFiles(crt_pid);

    /* see if this is a process or just a thread */
    mem_cmd_s = (char *)malloc(250 * sizeof(char));
    sprintf(mem_cmd_s, "%lf_%lf_%s", rsz, vsz, cmdName);
    if (getVectIndex(mem_cmd_s, mem_cmd_list, listSize) == -1) {
      /* aonther pid with the same command name, rsz and vsz was not found,
	 this is a new process and  we can add the amount of memory used 
	 by it */
      info -> pmem += pmem;
      info -> vsz += vsz; info -> rsz += rsz;

      if (info -> open_fd >= 0) /* if there was no error so far */
	info -> open_fd += open_fd;

      /* add an entry in the list so that next time we see another thread of
	 this process we don't add the amount of  memory again */
      mem_cmd_list[listSize++] = mem_cmd_s;     
    } else {
      free(mem_cmd_s);
    }
    /* if we monitor the current process, we have two extra opened files
       that we shouldn't take into account (the output file for ps and
       /proc/<pid>/fd/)
    */
    if (crt_pid == getpid())
      info -> open_fd -= 2;
    
  } 
  fclose(fp);
  unlink(ps_f);
  free(children);
  for (i = 0; i < listSize; i++) {
    free(mem_cmd_list[i]);
  }
  free(mem_cmd_list);
  return RET_SUCCESS;
}

long apMon_parsePSTime(char *s) {
  long days, hours, mins, secs;

  if (strchr(s, '-') != NULL) {
    sscanf(s, "%ld-%ld:%ld:%ld", &days, &hours, &mins, &secs);
    return 24 * 3600 * days + 3600 * hours + 60 * mins + secs;
  } else {
    if (strchr(s, ':') != NULL && strchr(s, ':') !=  strrchr(s, ':')) {
       sscanf(s, "%ld:%ld:%ld", &hours, &mins, &secs);
       return 3600 * hours + 60 * mins + secs;
    } else {
      if (strchr(s, ':') != NULL) {
	sscanf(s, "%ld:%ld", &mins, &secs);
	return 60 * mins + secs;
      } else {
	return RET_ERROR;
      }
    }
  }
}

int apMon_readJobDiskUsage(MonitoredJob job, JobDirInfo *info) {
  int status;
  pid_t cpid;
  long mypid = getpid();
  char *cmd, s_tmp[20], *argv[4], logmsg[100];
  FILE *fp;
  char du_f[50], df_f[50]; 

  /* generate names for the temporary files which will hold the output of the
     du and df commands */
  sprintf(du_f, "/tmp/out_du%ld", mypid);
  sprintf(df_f, "/tmp/out_df%ld", mypid);

  if (strlen(job.workdir) == 0)
    return RET_ERROR;
  
  cmd = (char *)malloc((100 + 2 * strlen(job.workdir)) * sizeof(char));
  strcpy(cmd, "PRT=`du -Lsk ");
  strcat(cmd, job.workdir);
  //strcat(cmd, " | tail -1 | cut -f 1 > ");
  strcat(cmd, " ` ; if [[ $? -eq 0 ]] ; then OUT=`echo $PRT | cut -f 1` ; echo $OUT ; exit 0 ; else exit -1 ; fi > "); 
  strcat(cmd, du_f);

  switch (cpid = fork()) {
  case -1:
    sprintf(logmsg, "Unable to fork(). The disk usage information could not be determined for %ld", job.pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  case 0:
    argv[0] = "/bin/sh"; argv[1] = "-c";
    argv[2] = cmd; argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      free(cmd);
      sprintf(logmsg, "The disc usage information for %ld could not be determined", job.pid);
      logger(WARNING, logmsg);
      return RET_ERROR; 
    }
  }
  
  strcpy(cmd, "PRT=`df -m ");
  strcat(cmd, job.workdir);
  //strcat(cmd, " | tail -1 > ");
  strcat(cmd, " `; if [[ $? -eq 0 ]] ; then OUT=`echo $PRT | cut -d ' ' -f 8-` ; echo $OUT ; exit 0 ; else exit -1 ; fi > ");
  strcat(cmd, df_f);

switch (cpid = fork()) {
  case -1:
    sprintf(logmsg, "Unable to fork(). The disk usage information could not be determined for %ld", job.pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  case 0:
    argv[0] = "/bin/sh"; argv[1] = "-c";
    argv[2] = cmd; argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      free(cmd);
      sprintf(logmsg, "The disc usage information for %ld could not be determined", job.pid);
      logger(WARNING, logmsg);
      return RET_ERROR; 
    }
  }


  free(cmd);
  fp = fopen(du_f, "rt");
  if (fp == NULL) {
    sprintf(logmsg, "Error opening du output file for process %ld", job.pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }

  fscanf(fp, "%lf", &(info -> workdir_size));
  /* keep the directory size in MB */
  info -> workdir_size /= 1024.0;
  fclose(fp);
  unlink(du_f);
 
  fp = fopen(df_f, "rt");
  if (fp == NULL) {
    sprintf(logmsg, "Error opening df output file for process %ld\n", job.pid);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }
 
  fscanf(fp, "%s %lf %lf %lf %lf", s_tmp, &(info -> disk_total), 
	 &(info -> disk_used), &(info -> disk_free), &(info -> disk_usage));
  fclose(fp);
  unlink(df_f);
  return RET_SUCCESS;
}
