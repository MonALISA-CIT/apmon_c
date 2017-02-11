/**
 * \file proc_utils.c
 * This file contains the implementations of the methods for extracting 
 * information from the proc filesystem.
 */

/*
 * ApMon - Application Monitoring Tool
 *
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

#include "utils.h"
#include "proc_utils.h"
#include "mon_constants.h"
#include "ApMon.h"

#include <dirent.h>

int procutils_updateCPUUsage(ApMon *apm) {
  FILE *fp1;
  char line[MAX_STRING_LEN];
  char s1[20];
  double usrTime, sysTime, niceTime, idleTime, totalTime;
  int indU, indS, indN, indI;

  time_t crtTime = time(NULL);
  fp1 = fopen("/proc/stat", "r");
  if (fp1 == NULL) {
    logger(WARNING,  "Could not open /proc/stat");
    return PROCUTILS_ERROR;
  }

  while (fgets(line, MAX_STRING_LEN, fp1)) {
      if (strstr(line, "cpu") == line)
	break;
  }

  fclose(fp1);
  if (line == NULL) {
    logger(WARNING, "Could not obtain CPU usage info from /proc/stat");
    return PROCUTILS_ERROR;
  }
 
  sscanf(line, "%s %lf %lf %lf %lf", s1, &usrTime, &niceTime, &sysTime, 
	 &idleTime);

  indU = getVectIndex( "cpu_usr", apm -> sysMonitorParams, 
		       apm -> nSysMonitorParams);
  indS = getVectIndex("cpu_sys", apm -> sysMonitorParams, 
		      apm -> nSysMonitorParams);
  indN = getVectIndex("cpu_nice", apm -> sysMonitorParams, 
		      apm -> nSysMonitorParams);
  indI = getVectIndex("cpu_idle", apm -> sysMonitorParams, 
		      apm -> nSysMonitorParams);
  if (idleTime < apm -> lastSysVals[indI]) {
    apm -> lastSysVals[indU] = usrTime;
    apm -> lastSysVals[indS] = sysTime;
    apm -> lastSysVals[indN] = niceTime;
    apm -> lastSysVals[indI] = idleTime;
    logger(WARNING, "CPU usage counter reset");
    return RET_ERROR;
  }
 
  if (apm -> numCPUs == 0) {
    logger(WARNING, "number of CPUs was not initialized");
    return PROCUTILS_ERROR;
  }
  if (crtTime <= apm -> lastSysInfoSend) {
    logger(WARNING, "Current time <= time of the previous sysInfoSend!");
    return RET_ERROR;
  }

  totalTime = (usrTime - apm -> lastSysVals[indU]) + 
    (sysTime - apm -> lastSysVals[indS]) +
    (niceTime - apm -> lastSysVals[indN]) + 
    (idleTime - apm -> lastSysVals[indI]);

  apm -> currentSysVals[SYS_CPU_USR] =  100 * (usrTime - 
			      apm -> lastSysVals[indU]) / totalTime;
  apm -> currentSysVals[SYS_CPU_SYS] = 100 * (sysTime - 
			      apm -> lastSysVals[indS]) / totalTime;
  apm -> currentSysVals[SYS_CPU_NICE] = 100 * (niceTime - 
			      apm -> lastSysVals[indN]) / totalTime;
  apm -> currentSysVals[SYS_CPU_IDLE] = 100 * (idleTime - 
			      apm -> lastSysVals[indI]) / totalTime;
  apm -> currentSysVals[SYS_CPU_USAGE] = 100 * (totalTime - (idleTime - 
				     apm -> lastSysVals[indI])) / totalTime;

  apm -> lastSysVals[indU] = usrTime;
  apm -> lastSysVals[indN] = niceTime;
  apm -> lastSysVals[indI] = idleTime;
  apm -> lastSysVals[indS] = sysTime; 

  return RET_SUCCESS;
}


int procutils_updateSwapPages(ApMon *apm) {
  FILE *fp1;
  char line[MAX_STRING_LEN];
  char s1[20];
  int foundPages, foundSwap;
  double p_in, p_out, s_in, s_out;
  int ind1, ind2;

  time_t crtTime = time(NULL);
  fp1 = fopen("/proc/stat", "r");
  if (fp1 == NULL) {
    logger(WARNING, "Could not open /proc/stat");
    return PROCUTILS_ERROR;
  }

  if (crtTime <= apm -> lastSysInfoSend) {
    logger(WARNING, "Current time <= time of the previous sysInfoSend!");
    return RET_ERROR;
  }

  foundPages = foundSwap = FALSE;
  while (fgets(line, MAX_STRING_LEN, fp1)) {
    if (strstr(line, "page") == line) {
      foundPages = TRUE;
      sscanf(line, "%s %lf %lf ", s1, &p_in, &p_out);

      ind1 = getVectIndex("pages_in", apm -> sysMonitorParams, 
			  apm -> nSysMonitorParams);
      ind2 = getVectIndex("pages_out", apm -> sysMonitorParams, 
			  apm -> nSysMonitorParams);
      if (p_in < apm -> lastSysVals[ind1] || p_out < apm -> lastSysVals[ind2]) {
	apm -> lastSysVals[ind1] = p_in;
	apm -> lastSysVals[ind2] = p_out;
	logger(WARNING, "pages in/out counter reset");
	return RET_ERROR;
      }
      apm -> currentSysVals[SYS_PAGES_IN] = (p_in - apm -> lastSysVals[ind1]) / 
	(crtTime - apm -> lastSysInfoSend);
      apm -> currentSysVals[SYS_PAGES_OUT] = (p_out - apm -> lastSysVals[ind2]) 
	/ (crtTime - apm -> lastSysInfoSend);
      apm -> lastSysVals[ind1] = p_in;
      apm -> lastSysVals[ind2] = p_out;

    }

    if (strstr(line, "swap") == line) {
      foundSwap = TRUE;
      sscanf(line, "%s %lf %lf ", s1, &s_in, &s_out);

      ind1 = getVectIndex("swap_in", apm -> sysMonitorParams, 
			  apm -> nSysMonitorParams);
      ind2 = getVectIndex("swap_out", apm -> sysMonitorParams, 
			  apm -> nSysMonitorParams);
      if (s_in < apm -> lastSysVals[ind1] || s_out < apm -> lastSysVals[ind2]) {
	apm -> lastSysVals[ind1] = s_in;
	apm -> lastSysVals[ind2] = s_out;
	logger(WARNING, "swap in/out counter reset");
	return RET_ERROR;
      }
      apm -> currentSysVals[SYS_SWAP_IN] = (s_in - apm -> lastSysVals[ind1]) / 
	(crtTime - apm -> lastSysInfoSend);
      apm -> currentSysVals[SYS_SWAP_OUT] = (s_out - apm -> lastSysVals[ind2]) 
	/ (crtTime - apm -> lastSysInfoSend);
      apm -> lastSysVals[ind1] = s_in;
      apm -> lastSysVals[ind2] = s_out;

    }
  }
   
  fclose(fp1);

  if (!foundPages || !foundSwap) {
    logger(INFO, "Could not obtain swap/pages in/out from /proc/stat");
    return PROCUTILS_ERROR;
  }

  return RET_SUCCESS;
}

int procutils_updateLoad(ApMon *apm) {
  double v1, v5, v15, activeProcs, totalProcs;
  FILE *fp1;

  fp1 = fopen("/proc/loadavg", "r");
  if (fp1 == NULL) {
    logger(WARNING, "Could not open /proc/loadavg");
    return PROCUTILS_ERROR;
  }

  fscanf(fp1, "%lf %lf %lf", &v1, &v5, &v15);
  apm -> currentSysVals[SYS_LOAD1] = v1;
  apm -> currentSysVals[SYS_LOAD5] = v5;
  apm -> currentSysVals[SYS_LOAD15] = v15;

  fscanf(fp1, "%lf/%lf", &activeProcs, &totalProcs);
  apm -> currentSysVals[SYS_PROCESSES] = totalProcs;
  fclose(fp1);

  return RET_SUCCESS;
}

int procutils_getSysMem(double *totalMem, double *totalSwap) {
  char s1[20], line[MAX_STRING_LEN];
  int memFound = FALSE, swapFound = FALSE;
  double valMem, valSwap;
  FILE *fp1;

  fp1 = fopen("/proc/meminfo", "r");
  if (fp1 == NULL) {
    logger(WARNING, "Could not open /proc/meminfo");
    return PROCUTILS_ERROR;
  }

  while (fgets(line, MAX_STRING_LEN, fp1)) {
    if (strstr(line, "MemTotal:") == line) {
      sscanf(line, "%s %lf", s1, &valMem);
      memFound = TRUE;
      continue;
    }

    if (strstr(line, "SwapTotal:") == line) {
      sscanf(line, "%s %lf", s1, &valSwap);
      swapFound = TRUE;
      continue;
    }
    
  }
  fclose(fp1); 

  if (!memFound || !swapFound) {
    logger(WARNING, "Could not obtain memory info from /proc/meminfo");
    return PROCUTILS_ERROR;
  }
  *totalMem = valMem / 1024;
  *totalSwap = valSwap / 1024;
  return RET_SUCCESS;
}

int procutils_updateMemUsed(ApMon *apm) {
  double mFree = 0, mTotal = 0, sFree = 0, sTotal = 0;
  char s1[20], line[MAX_STRING_LEN];
  int mFreeFound = FALSE, mTotalFound = FALSE;
  int sFreeFound = FALSE, sTotalFound = FALSE;
  FILE *fp1;

  fp1 = fopen("/proc/meminfo", "r");
  if (fp1 == NULL) {
    logger(WARNING, "Could not open /proc/meminfo");
    return PROCUTILS_ERROR;
  }

  while (fgets(line, MAX_STRING_LEN, fp1)) {
    if (strstr(line, "MemTotal:") == line) {
      sscanf(line, "%s %lf", s1, &mTotal);
      mTotalFound = TRUE;
      continue;
    }

    if (strstr(line, "MemFree:") == line) {
      sscanf(line, "%s %lf", s1, &mFree);
      mFreeFound = TRUE;
      continue;
    }

    if (strstr(line, "SwapTotal:") == line) {
      sscanf(line, "%s %lf", s1, &sTotal);
      sTotalFound = TRUE;
      continue;
    }

    if (strstr(line, "SwapFree:") == line) {
      sscanf(line, "%s %lf", s1, &sFree);
      sFreeFound = TRUE;
      continue;
    }
    
  }
  fclose(fp1); 

  if (!mFreeFound || !mTotalFound || !sFreeFound || !sTotalFound) {
    logger(WARNING, "Could not obtain memory info from /proc/meminfo");
    return PROCUTILS_ERROR;
  }
  apm -> currentSysVals[SYS_MEM_USED] = (mTotal - mFree) / 1024;
  apm -> currentSysVals[SYS_MEM_FREE] = mFree / 1024;
  apm -> currentSysVals[SYS_SWAP_USED] = (sTotal - sFree) / 1024;
  apm -> currentSysVals[SYS_SWAP_USAGE] = sFree / 1024;

  apm -> currentSysVals[SYS_MEM_USAGE] = 100 * apm -> currentSysVals[SYS_MEM_USED] /
	(apm -> currentSysVals[SYS_MEM_USED] +  apm -> currentSysVals[SYS_MEM_FREE]); 
  apm -> currentSysVals[SYS_SWAP_USAGE] = 100 * apm -> currentSysVals[SYS_SWAP_USED] /
    (apm -> currentSysVals[SYS_SWAP_USED] +  apm -> currentSysVals[SYS_SWAP_FREE]); 
  return RET_SUCCESS;
}

int procutils_getNetworkInterfaces(int *nInterfaces, 
				    char names[][20]) {
  char line[MAX_STRING_LEN], *tmp, buf[MAX_STRING_LEN];
  char *pbuf = buf;
  FILE *fp1;

  *nInterfaces = 0;

  fp1 = fopen("/proc/net/dev", "r");
  if (fp1 == NULL) {
    logger(WARNING, "getNetworkInterfaces(): Could not open /proc/net/dev");
    return PROCUTILS_ERROR; 
  }
  while (fgets(line, MAX_STRING_LEN, fp1)) {
    if (strchr(line, ':') == NULL)
      continue;

    tmp = strtok_r(line, " :", &pbuf);

    if (strcmp(tmp, "lo") == 0)
      continue;
    
    strcpy(names[*nInterfaces], tmp);
    (*nInterfaces)++;
  }
    
  fclose(fp1);
  return RET_SUCCESS;
}

int procutils_getNetInfo(ApMon *apm) {
			       
  double *netIn, *netOut,*netErrs, bytesReceived, bytesSent;
  int errs;
  char line[MAX_STRING_LEN];
  char buf[MAX_STRING_LEN], logmsg[100];
  char *pbuf = buf;
  char *tmp, *tok;
  double bootTime = 0;
  FILE *fp1;
  time_t crtTime = time(NULL);
  int ind, i;
 
  if (apm -> lastSysInfoSend == 0) {
    bootTime = procutils_getBootTime();
   
    if (bootTime == PROCUTILS_ERROR) {
      bootTime = 0;
      logger(WARNING, "Error obtaining boot time. The first system monitoring datagram will contain incorrect data.");
    }
  } else {
    if (crtTime <= apm -> lastSysInfoSend) {
      logger(WARNING, "Current time <= time of the previous sysInfoSend!");
      return RET_ERROR;
    }
  }

  fp1 = fopen("/proc/net/dev", "r");
  if (fp1 == NULL) {
    logger(WARNING, "Could not open /proc/net/dev");
    return PROCUTILS_ERROR;
  }

  netIn = (double *)malloc(apm -> nInterfaces * sizeof(double));
  netOut = (double *)malloc(apm -> nInterfaces * sizeof(double));
  netErrs = (double *)malloc(apm -> nInterfaces * sizeof(double));

  while (fgets(line, MAX_STRING_LEN, fp1)) {
    if (strchr(line, ':') == NULL)
      continue;
    tmp = strtok_r(line, " :", &pbuf);
    
    /* the loopback interface is not considered */
    if (strcmp(tmp, "lo") == 0)
      continue;

    /* find the index of the interface in the vector */
    ind = -1;
    for (i = 0; i < apm -> nInterfaces; i++)
      if (strcmp(apm -> interfaceNames[i], tmp) == 0) {
	ind = i;
	break;
      }
    
    if (ind < 0) {
      fclose(fp1);
      free(netIn); free(netOut); free(netErrs);
      sprintf(logmsg, "Could not find interface %s in /proc/net/dev", tmp); 
      logger(WARNING, logmsg);
      return RET_ERROR;
    }
    /* parse the rest of the line */
    tok = strtok_r(NULL, " ", &pbuf);
    bytesReceived = atof(tok); /* bytes received */
    tok = strtok_r(NULL, " ", &pbuf); /* packets received */
    tok = strtok_r(NULL, " ", &pbuf); /* input errors */
    errs = atoi(tok);

    /* some parameters that we are not monitoring */
    for (i = 1; i <= 5; i++)
      tok = strtok_r(NULL, " ", &pbuf);

    tok = strtok_r(NULL, " ", &pbuf); /* bytes transmitted */
    bytesSent = atof(tok);
    tok = strtok_r(NULL, " ", &pbuf); /* packets transmitted */
    tok = strtok_r(NULL, " ", &pbuf); /* output errors */
    errs += atoi(tok);

    /* printf("### bytesReceived %lf lastRecv %lf\n", bytesReceived, 
       lastBytesReceived[ind]); */
    if (bytesReceived < apm -> lastBytesReceived[ind] || bytesSent < 
	apm -> lastBytesSent[ind] || errs < apm -> lastNetErrs[ind]) {
      apm -> lastBytesReceived[ind] = bytesReceived;
      apm -> lastBytesSent[ind] = bytesSent;
      apm -> lastNetErrs[ind] = errs;
      fclose(fp1);
      free(netIn); free(netOut); free(netErrs);
      logger(WARNING, "Network interface(s) restarted.");
      return RET_ERROR;
    }

    if (apm -> lastSysInfoSend == 0) {
      netIn[ind] = bytesReceived/(crtTime - bootTime);
      netOut[ind] = bytesSent/(crtTime - bootTime);
      netErrs[ind] = errs;
    }
    else {
      netIn[ind] = (bytesReceived - apm -> lastBytesReceived[ind]) / (crtTime -
						     apm  -> lastSysInfoSend);
      netIn[ind] /= 1024; /* netIn is measured in KBps */
      netOut[ind] = (bytesSent - apm -> lastBytesSent[ind]) / (crtTime - 
						     apm -> lastSysInfoSend);
      netOut[ind] /= 1024; /* netOut is measured in KBps */
      netErrs[ind] = errs - apm -> lastNetErrs[ind];
    }

    apm -> lastBytesReceived[ind] = bytesReceived;
    apm -> lastBytesSent[ind] = bytesSent;
    apm -> lastNetErrs[ind] = errs;
  }
    
  fclose(fp1);
  apm -> currentNetIn = netIn;
  apm -> currentNetOut = netOut;
  apm -> currentNetErrs = netErrs;
  return RET_SUCCESS;
}


int procutils_getNumCPUs() {
  int numCPUs = 0;
  char line[MAX_STRING_LEN];

  FILE *fp = fopen("/proc/stat", "r");

  if (fp == NULL) {
    logger(WARNING, "Could not open /proc/stat.");
    return PROCUTILS_ERROR;
  }

  while(fgets(line, MAX_STRING_LEN, fp)) {
    if (strstr(line, "cpu") == line && isdigit(line[3]))
      numCPUs++;
  }

  fclose(fp);
  return numCPUs;
}

int procutils_getCPUInfo(ApMon *apm) {
  double freq = 0;
  char line[MAX_STRING_LEN], s1[100], s2[100], s3[100];
  char buf[MAX_STRING_LEN];
  char *pbuf = buf, *tmp, *tmp_trim;
  int freqFound = FALSE, bogomipsFound = FALSE;

  FILE *fp = fopen("/proc/cpuinfo", "r");
  if (fp == NULL) {
    logger(WARNING, "[ apMon_getCPUInfo() ] Could not open /proc/cpuinfo");
    return RET_ERROR;
  }

  while (fgets(line, MAX_STRING_LEN, fp)) {
    if (strstr(line, "cpu MHz") == line) {
      sscanf(line, "%s %s %s %lf", s1, s2, s3, &freq);
      apm -> currentGenVals[GEN_CPU_MHZ] = freq;
      freqFound = TRUE;
      continue;
    }

    if (strstr(line, "bogomips") == line) {
      sscanf(line, "%s %s %lf", s1, s2, &(apm -> currentGenVals[GEN_BOGOMIPS]));
      bogomipsFound = TRUE;
      continue;
    }

    if (strstr(line, "vendor_id") == line) {
      tmp = strtok_r(line, ":", &pbuf);
      /* take everything that's after the ":" */
      tmp = strtok_r(NULL, ":", &pbuf);
      tmp_trim = trimString(tmp);
      strcpy(apm -> cpuVendor, tmp_trim);
      free(tmp_trim);
      continue;
    } 

    if (strstr(line, "cpu family") == line) {
      tmp = strtok_r(line, ":", &pbuf);
      tmp = strtok_r(NULL, ":", &pbuf);
      tmp_trim = trimString(tmp);
      strcpy(apm -> cpuFamily, tmp_trim);
      free(tmp_trim);
      continue;
    }

    if (strstr(line, "model") == line && strstr(line, "model name") != line) {
      tmp = strtok_r(line, ":", &pbuf);
      tmp = strtok_r(NULL, ":", &pbuf);
      tmp_trim = trimString(tmp);
      strcpy(apm -> cpuModel, tmp_trim);
      free(tmp_trim);
      continue;
    }  

    if (strstr(line, "model name") == line) {
      tmp = strtok_r(line, ":", &pbuf);
      /* take everything that's after the ":" */
      tmp = strtok_r(NULL, ":", &pbuf);
      tmp_trim = trimString(tmp);
      strcpy(apm -> cpuModelName, tmp_trim);
      free(tmp_trim);
      continue;
    } 
  }

  fclose(fp);
  if (!freqFound || !bogomipsFound) {
    logger(WARNING, "[ apmon_getCPUInfo() ] Could not find frequency or bogomips in /proc/cpuinfo");
    return RET_ERROR;
  }
  return RET_SUCCESS;
}


/**
 * Returns the system boot time in seconds since the Epoch.
 */
long procutils_getBootTime() {
  char line[MAX_STRING_LEN], s[MAX_STRING_LEN];
  long btime = 0;
  FILE *fp = fopen("/proc/stat", "rt");
  if (fp == NULL) {
    logger(WARNING, "Could not open /proc/stat");
    return PROCUTILS_ERROR;
  }

  while (fgets(line, MAX_STRING_LEN, fp)) {
    if (strstr(line, "btime") == line) {
      sscanf(line, "%s %ld", s, &btime);
      break;
    }
  }  
  fclose(fp);

  if (btime == 0) {
    logger(WARNING, "Could not find boot time in /proc/stat");
    return RET_ERROR;
  }
  return btime;
}

/**
 * Returns the system uptime in days.
 */
double procutils_getUpTime() {
  double uptime = 0;
  FILE *fp = fopen("/proc/uptime", "rt");
  if (fp == NULL) {
    logger(WARNING, "Could not open /proc/uptime");
    return PROCUTILS_ERROR;
  }

  fscanf(fp, "%lf", &uptime);
  fclose(fp);

  if (uptime <= 0) {
    logger(WARNING, "Could not find uptime in /proc/uptime");
    return RET_ERROR;
  }
  return uptime / (24 * 3600);
}


int procutils_getProcesses(double *processes, double states[]) {
  char *argv[4];
  char psstat_f[50];
  long mypid = (long)getpid();
  pid_t cpid;
  int status, i;
  char ch, buf[100];
  FILE *pf;

  sprintf(psstat_f, "/tmp/apmon_psstat%ld", mypid);

 switch (cpid = fork()) {
  case -1:
    logger(WARNING, "[ getProcesses() ] Unable to fork()");
    return RET_ERROR;
  case 0:
    argv[0] = "/bin/sh"; argv[1] = "-c";
    sprintf(buf, "ps -e -A -o state > %s",
	    psstat_f);
    argv[2] = buf;
    argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      logger(WARNING, "[ getProcesses() ] The number of processes could not be determined");
      return RET_ERROR;
    }
  }

  pf = fopen(psstat_f, "rt");
  if (pf == NULL) {
    unlink(psstat_f);
    logger(WARNING, "[ getProcesses() ] The number of processes could not be determined");
    return RET_ERROR;
  } 

  *processes = 0;
  // the states table keeps an entry for each alphabet letter, for efficient 
  // indexing
  for (i = 0; i < NLETTERS; i++)
    states[i] = 0.0;
  while (fgets(buf, 10, pf) > 0) {
    ch = buf[0];
    states[ch - 65]++;
    (*processes)++;
  }

  fclose(pf);   
  unlink(psstat_f);
  return RET_SUCCESS;
}

int procutils_countOpenFiles(long pid) {
  char dirname[50];
  char msg[MAX_STRING_LEN];
  DIR *dir;
  struct dirent *dir_entry;
  int cnt = 0;
 
  /* in /proc/<pid>/fd/ there is an entry for each opened file descriptor */
  sprintf(dirname, "/proc/%ld/fd", pid);
  dir = opendir(dirname);
  if (dir == NULL) {
    sprintf(msg, "[ countOpenFiles() ] Could not open %s", dirname); 
    logger(WARNING, msg);
    return PROCUTILS_ERROR;
  }

  /* count the files from /proc/<pid>/fd/ */
  while ((dir_entry = readdir(dir)) != NULL) {
    cnt++;
  }
  
  closedir(dir);

  /* don't take into account . and .. */
  cnt -= 2;
  if (cnt < 0) {
    sprintf(msg, "[ countOpenFiles() ] Directory %s has less than 2 entries", 
	    dirname);
    logger(FINE, msg);
    cnt = 0;
  }

  return cnt;
}

int procutils_getNetstatInfo(ApMon *apm) {
  char *argv[4];
  char netstat_f[50];
  long mypid = (long)getpid();
  pid_t cpid;
  int status, i, idx;
  char buf[100], msg[100];
  char *pbuf = buf, *tmp, *tmp2;
  FILE *pf;

  sprintf(netstat_f, "/tmp/apmon_netstat%ld", mypid);

  switch (cpid = fork()) {
  case -1:
    logger(WARNING, "[ getNetstatInfo() ] Unable to fork()");
    return RET_ERROR;
  case 0:
    argv[0] = "/bin/sh"; argv[1] = "-c";
    sprintf(buf, "netstat -an > %s",
	    netstat_f);
    argv[2] = buf;
    argv[3] = 0;
    execv("/bin/sh", argv);
    exit(RET_ERROR);
  default:
    if (waitpid(cpid, &status, 0) == -1) {
      sprintf(msg, "[ getNetstatInfo() ] The netstat information could not be collected");
      logger(WARNING, msg);
      return RET_ERROR; 
    }
  }

  pf = fopen(netstat_f, "rt");
  if (pf == NULL) {
    unlink(netstat_f);
    logger(WARNING, "[ getNetstatInfo() ] The netstat information could not be collected");
    return RET_ERROR;
  } 

  // the states table keeps an entry for each alphabet letter, for efficient 
  // indexing
  for (i = 0; i < 4; i++)
    apm -> currentNSockets[i] = 0.0;
  for (i = 0; i < N_TCP_STATES; i++)
    apm -> currentSocketsTCP[i] = 0.0;

  while (fgets(buf, 200, pf) > 0) {
    tmp = strtok_r(buf, " \t\n", &pbuf);
    if (strstr(tmp, "tcp") == tmp) {
      (apm -> currentNSockets[SOCK_TCP])++;

      /* go to the "State" field */
      for (i = 1; i <= 5; i++)
	tmp2 = strtok_r(NULL, " \t\n", &pbuf);

      idx = getVectIndex(tmp2, apm -> socketStatesMapTCP, N_TCP_STATES);
      if (idx >= 0) {
	(apm -> currentSocketsTCP[idx])++;
      } else {
	sprintf(msg, "[ getNestatInfo() ] Invalid socket state: %s q", tmp2);
	logger(WARNING, msg);
      }
    } else {
      if (strstr(tmp, "udp") == tmp) {
	(apm -> currentNSockets[SOCK_UDP])++;
      } else {
	if (strstr(tmp, "unix") == tmp)
	  (apm -> currentNSockets[SOCK_UNIX])++;
	else if (strstr(tmp, "icm") == tmp)
	  (apm -> currentNSockets[SOCK_ICM])++;
      }
    }
  }

  fclose(pf);   
  unlink(netstat_f);
  return RET_SUCCESS;
}
