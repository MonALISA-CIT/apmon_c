/**
 * \file ApMon.c
 * This file contains the implementations of the functions declared in 
 * ApMon.h and some additional helper functions.
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
#include "utils.h"
#include "proc_utils.h"
#include "monitor_utils.h"
#include "mon_constants.h"

#include <math.h>

#define RECHECK_CONF 0
#define SYS_INFO_SEND 1
#define JOB_INFO_SEND 2

char boolStrings[][10] = {"false", "true"};

/* ================= Internal functions ==================== */

 /**
  * Internal function that initializes an ApMon data structure.
  * @param nDestinations The number of destination hosts where the results will
  * be sent.
  * @param destAddresses Array that contains the hostnames or IP addresses 
  * of the destination hosts.
  * @param destPorts The ports where the MonaLisa modules listen on the 
  * destination hosts.
  * @param destPasswds Passwords for the destination hosts.
  * @param firstTime If it is 1(TRUE), all the initializations will be done (the
  * object is being constructed now). If it is 0(FALSE), only some structures 
  * will be reinitialized.
  * @param apm_orig The ApMon object that we wish to reinitialize (considered
  * only if firstTime is TRUE)
  */
ApMon *apMon_arrayInit_f(int nDestinations, char **destAddresses, int *destPorts,
		 char **destPasswds, int firstTime, ApMon *apm_orig, MonitorConf mconf);

/**
 * Initializes an ApMon object from a configuration file.
 * @param filename The name of the file which contains the addresses and
 * the ports of the destination hosts (see README for details about
 * the structure of this file).
 * @param firstTime If it is 1(TRUE), all the initializations will be done (the
 * object is being constructed now). Else, only some structures will be 
 * reinitialized.
 * @param apm_orig The ApMon object that we wish to reinitialize (considered
  * only if firstTime is TRUE)
 */
ApMon *apMon_init_f(char *filename, int firstTime, ApMon *apm_orig);

/**
 * Initializes an ApMon object from a list with URLs.
 * @param nDestinations The number of elements in destList.
 * @param destList The list with URLs.
 * @param firstTime If it is nonzero, all the initializations will be done 
 * (the object is being constructed now). Else, only some structures will 
 * be reinitialized.
 * @param apm_orig The ApMon object that we wish to reinitialize (considered
 * only if firstTime is TRUE)
 */
ApMon *apMon_stringInit_f(char *destList, int firstTime,
			  ApMon *apm_orig);

/**
 * Parses the string line, which has the form hostname:port, and
 * adds the hostname and the port to the lists given as parameters.
 * @param line The line to be parsed.
 * @param nDestinations The number of destination hosts in the lists.
 * Will be modified (incremented) in the function.
 * @param destAddresses The list with IP addresses or hostnames.
 * @param destPorts The list of corresponding ports.
 * @param destPasswds The passwords for the MonALISA hosts.
 */ 
int addToDestinations(char *line, int *nDestinations, 
       char *destAddresses[], int destPorts[], char *destPasswds[]); 

/**
 * Gets a configuration file from a web location and adds the destination
 * addresses and ports to the lists given as parameters.
 */
int getDestFromWeb(MonitorConf *mconf, char *url, int *nDestinations, char *destAddresses[], 
    int destPorts[], char *destPasswds[], ConfURLs *confURLs);


/**
 * Encodes in the XDR format the data from a ApMon structure. Must be 
 * called before sending the data over the newtork.
 * @param apm Pointer to the ApMon data structure.
 */ 
int apMon_encodeParams(ApMon *apm, int nParams, char **paramNames, 
		       int *valueTypes, char **paramValues, int timestamp);

/**
 * This function is executed in a background thread and has two 
 * roles: it automatically sends the system/job monitoring parameters (if
 * the user requested) and it checks the configuration file/URLs for 
 * changes.
 */
void *bkTask(void *param);

void apMon_setBackgroundThread(ApMon *apm, int val);

void apMon_setCrtRecheckInterval(ApMon *apm, long val);

int apMon_parseConf(FILE *fp, int *nDestinations, char **destAddresses, 
		    int *destPorts, char **destPasswds, MonitorConf *mconf);

/**
 * Frees the data structures needed to hold the configuratin settings.
 */
void apMon_freeConf(ApMon *apm);

/** Initializes the UDP socket used to send the datagrams. */
int apMon_initSocket(ApMon *apm);

/**
 * Decides if the current datagram should be sent (so that the maximum
 * number of datagrams per second is respected in average).
 * This decision is based on the number of messages previously sent.
 */ 
int apMon_shouldSend(ApMon *apm);


/* ========= Implementations of the functions =================== */

ApMon *apMon_init(char *initsource) {

  if (initsource == NULL) {
    logger(FATAL, "[ apMon_init() ]  No conf file/URL provided");
    return NULL;
  }

  if (strstr(initsource, "http://") == initsource) {    
    return apMon_stringInit(initsource);
  } else {
    ApMon *apm = apMon_init_f(initsource, TRUE, NULL);
  
    if (apm == NULL) return NULL;

    apm -> initType = FILE_INIT;
    apm -> initSource = strdup(initsource);

    return apm;
  }
}

ApMon *apMon_init_f(char *filename, int firstTime, ApMon *apm_orig) {  
  ApMon *apm;
  MonitorConf mconf;
  FILE *f;
  char *destAddresses[MAX_N_DESTINATIONS];
  int destPorts[MAX_N_DESTINATIONS];
  char *destPasswds[MAX_N_DESTINATIONS];
  ConfURLs confURLs;
  int nDestinations = 0;
  int ret, i;
  char logmsg[100];
  /* struct stat st; */

  /* initializations for the destination addresses */
  f = fopen(filename, "rt");
  if (f == NULL) {
    sprintf(logmsg, "Error opening file %s", filename);
    logger(WARNING, logmsg);
    return NULL;
  }

  logger(INFO, "Initializing destination addresses & ports:");

  apMon_initMonitoring(&mconf);
  confURLs.nConfURLs = 0;

  ret = apMon_parseConf(f, &nDestinations, destAddresses, 
			destPorts, destPasswds, &mconf);

  fclose(f);
  /* only modify the configuration if we successfully loaded the URLs */
  if (ret != RET_ERROR) {
    apm = apMon_arrayInit_f(nDestinations, destAddresses, destPorts, 
			    destPasswds, firstTime, apm_orig, mconf);    

    for (i = 0; i < nDestinations; i++) {
      free(destAddresses[i]);
      free(destPasswds[i]);
    }

    if (apm == NULL)
      return NULL;

    /* stat(apm -> initSource, &st); */
    apm -> lastModifFile = time(NULL); /* st.st_mtime; */

    pthread_mutex_lock(&apm -> mutex);
    apm -> confURLs = confURLs;
    pthread_mutex_unlock(&apm -> mutex);
  }
 
  return apm;
}

ApMon *apMon_stringInit(char *destinationsList) {
  ApMon *apm = apMon_stringInit_f(destinationsList, TRUE, NULL);
  if (apm == NULL)
    return NULL;

  apm -> initType = LIST_INIT_APMON;
  /*
  pthread_mutex_init(&apm -> mutex, NULL);
  pthread_mutex_init(&apm -> mutexBack, NULL);
  pthread_mutex_init(&apm -> mutexCond, NULL);
  pthread_cond_init(&apm -> confChangedCond, NULL);

  apm -> bkThreadStarted = FALSE;
  */

  /* save the initialization list */
  apm -> initSource = strdup(destinationsList);
  return apm;
}

ApMon *apMon_stringInit_f(char *destinationsList, int firstTime, 
    ApMon *apm_orig) {
  ApMon *apm;
  MonitorConf mconf;
  char *destAddresses[MAX_N_DESTINATIONS];
  int destPorts[MAX_N_DESTINATIONS];
  char *destPasswds[MAX_N_DESTINATIONS];
  int nDestinations = 0;
  ConfURLs confURLs;
  char tok[MAX_STRING_LEN], *tmp;
  int ret;
  int i, j, k;
  
  logger(INFO, "Initializing ApMon...");
  if (destinationsList == NULL) {
    logger(FATAL, "[ apMon_stringInit_f() ] The initialization list is NULL!");
    return NULL;
  }

  confURLs.nConfURLs = 0;
  apMon_initMonitoring(&mconf);

  /* parse the string */
  j = 0;
  for (i = 0; i < strlen(destinationsList); i++) {
   
    if ((destinationsList[i] == ',') || (i == strlen(destinationsList) - 1)) { 
      /* token finished */
      if (i == strlen(destinationsList) - 1)
	tok[j++] = destinationsList[i];
      tok[j++] = 0;
      tmp = trimString(tok);
      if (strstr(tmp, "http") == tmp) {
	ret = getDestFromWeb(&mconf, tmp, &nDestinations, destAddresses, destPorts,
			     destPasswds, &confURLs);
      } else {
	if (nDestinations >= MAX_N_DESTINATIONS) {
	  logger(WARNING, "Maximum number of destinations exceeded");
	  return NULL;
	}
	ret = addToDestinations(tmp, &nDestinations, destAddresses, destPorts,
				destPasswds);
      }

      free(tmp);
      if (ret == RET_ERROR) {
	for (k = 0; k < nDestinations; k++) {
	  free(destAddresses[k]);
	  free(destPasswds[k]);
	}
	//if (firstTime)
	return NULL;
      }
      j = 0;
    } else 
      tok[j++] = destinationsList[i];
  }

  if (ret != RET_ERROR) {
    apm = apMon_arrayInit_f(nDestinations, destAddresses, destPorts, 
			    destPasswds, firstTime, apm_orig, mconf);
    for (k = 0; k < nDestinations; k++) {
      free(destAddresses[k]);
      free(destPasswds[k]);
    }

    if (apm == NULL)
      return NULL;
    pthread_mutex_lock(&apm -> mutex);
    apm -> confURLs = confURLs;
    pthread_mutex_unlock(&apm -> mutex);
  }
  return apm;

}

int addToDestinations(char *line, int *nDestinations, 
       char *destAddresses[], int destPorts[], char *destPasswds[]) {

  char *addr, *port, *passwd;
  char *sep1 = " \t";
  char *sep2 = ":";
  char *tmp = strdup(line);
  char *firstToken;
  char buf[MAX_STRING_LEN];
  char *pbuf = buf;

  /* the address & port are separated from the password with spaces */
  firstToken = strtok_r(tmp, sep1, &pbuf);
  passwd = strtok_r(NULL, sep1, &pbuf);

  /* the address and the port are separated with ":" */
  addr = strtok_r(firstToken, sep2, &pbuf);
  port = strtok_r(NULL, sep2, &pbuf);
  destAddresses[*nDestinations] = strdup(addr);
  if (port == NULL) {
    destPorts[*nDestinations] = DEFAULT_PORT;
  } else {
    destPorts[*nDestinations] = atoi(port);
  }
  if (passwd == NULL)
    destPasswds[*nDestinations] = strdup("");
  else
    destPasswds[*nDestinations] = strdup(passwd);

  (*nDestinations)++;
  free(tmp);
  return RET_SUCCESS;
}
  
int getDestFromWeb(MonitorConf *mconf, char *url, int *nDestinations, 
  char *destAddresses[], int destPorts[], char *destPasswds[], 
		   ConfURLs *confURLs) {
  char temp_filename[30]; 
  char str1[20], str2[20];
  char *line, *ret, *tmp = NULL;
  FILE *tmp_file;
  int modifLineFound;
  int retVal;
  long mypid = getpid();
  sprintf(temp_filename, "/tmp/temp_file%ld", mypid);
 
 /* get the configuration file from web and put it in a temporary file */
  retVal = httpRequest(url, "GET", temp_filename);
  if (retVal == RET_ERROR)
    return RET_ERROR;

  /* read the configuration from the temporary file */
  tmp_file = fopen(temp_filename, "rt");
  line = (char*)malloc(MAX_STRING_LEN * sizeof(char));

  /* check the HTTP header to see if we got the page correctly */
  fgets(line, MAX_STRING_LEN, tmp_file);
  sscanf(line, "%s %s", str1, str2);
  if (atoi(str2) != 200) {
    logger(WARNING, "The requested page does not exist on the HTTP server");
    fclose(tmp_file); free(line);
    return RET_ERROR;
  }

  confURLs -> vURLs[confURLs -> nConfURLs] = strdup(url);

  /* check the  header for the "Last-Modified" line */
  modifLineFound = FALSE;
  do {
    if (tmp != NULL)
      free(tmp);
    ret = fgets(line, MAX_STRING_LEN, tmp_file);
    if (ret == NULL) {
      logger(WARNING, "Invalid answer from the HTTP server");
      fclose(tmp_file); free(line);
      return RET_ERROR;
    }

    if (strstr(line, "Last-Modified") == line) {
      modifLineFound = TRUE;
      confURLs -> lastModifURLs[confURLs -> nConfURLs] = strdup(line);
    }

    tmp = trimString(line);
    /* printf("%s  -- length %d \n", line, strlen(line)); */
  } while (strlen(tmp) != 0);
  free(tmp);

  if (!modifLineFound)
    confURLs -> lastModifURLs[confURLs -> nConfURLs] = "";
  confURLs -> nConfURLs++;

  retVal = apMon_parseConf(tmp_file, nDestinations, destAddresses, 
		  destPorts, destPasswds, mconf);

  free(line);
  fclose(tmp_file);
  /* delete the temporary file */
  unlink(temp_filename);

  return retVal;
}


ApMon* apMon_arrayInit(int nDestinations, char **destAddresses, 
		       int *destPorts, char **destPasswds) {
  MonitorConf mconf;
  ApMon *apm;

  apMon_initMonitoring(&mconf);
  apm = apMon_arrayInit_f(nDestinations, destAddresses, destPorts, 
			 destPasswds, TRUE, NULL, mconf);
  apm -> initType = DIRECT_INIT;

  /*
  pthread_mutex_init(&apm -> mutex, NULL);
  pthread_mutex_init(&apm -> mutexBack, NULL);
  pthread_mutex_init(&apm -> mutexCond, NULL);
  pthread_cond_init(&apm -> confChangedCond, NULL);
  apm -> bkThreadStarted = FALSE;
  */

  return apm;
}

ApMon* apMon_arrayInit_f(int nDestinations, char **destAddresses, 
    int *destPorts, char **destPasswds, int firstTime, ApMon *apm_orig, MonitorConf mconf) {
  ApMon *apm;
  int i, j, ret, found, sockd;
  int havePublicIP;
  char *ipAddr, ip[4], tmp_s[30];
  int tmpNDestinations;
  char **tmpAddresses, **tmpPasswds;
  int *tmpPorts;
  struct ifreq ifr;
  char logmsg[100];

  /* initializations that we need to do only once */
  if (firstTime) {
    apm = (ApMon *)malloc(sizeof(ApMon));

    apm -> nMonJobs = 0;
    apm -> monJobs = (MonitoredJob *)malloc(MAX_MONITORED_JOBS * 
					    sizeof(MonitoredJob));   

    apMon_copyParamNames(apm, mconf);
    apm -> recheckChanged = FALSE;
    apm -> jobMonChanged = FALSE;
    apm -> sysMonChanged = FALSE;

    apm -> sysInfo_first = TRUE;
    ret = procutils_getBootTime();
    if (ret == PROCUTILS_ERROR) {
      logger(WARNING, "The first system monitoring values may be inaccurate");
      apm -> lastSysInfoSend = 0;
    } else {
      apm -> lastSysInfoSend = ret;
    }

    for (i = 0; i < apm -> nSysMonitorParams; i++) {
      apm -> sysRetResults[i] = RET_SUCCESS;
    }

    for (i = 0; i < apm -> nGenMonitorParams; i++) {
      apm -> genRetResults[i] = RET_SUCCESS;
    }

    for (i = 0; i < apm -> nJobMonitorParams; i++) {
      apm -> jobRetResults[i] = RET_SUCCESS;
    }

    for (i = 0; i < apm -> nSysMonitorParams; i++)
      apm -> lastSysVals[i] = 0;

    initSocketStatesMapTCP(apm -> socketStatesMapTCP);

    /*
    for (i = 0; i < apm -> nSysMonitorParams; i++)
      apm -> lastValues[i] = 0;

    apm -> lastUsrTime = apm -> lastSysTime = 0;
    apm -> lastNiceTime = apm -> lastIdleTime = 0;
    */

    apm -> nInterfaces = 0;
    apm -> numCPUs = procutils_getNumCPUs();
    if (apm -> numCPUs <= 0) {
      logger(WARNING, "Could not find the number of CPUs");
    }

    pthread_mutex_init(&apm -> mutex, NULL);
    pthread_mutex_init(&apm -> mutexBack, NULL);
    pthread_mutex_init(&apm -> mutexCond, NULL);
    pthread_cond_init(&apm -> confChangedCond, NULL);
    apm -> haveBkThread = FALSE;
    apm -> bkThreadStarted = FALSE;
    apm -> stopBkThread = FALSE;

    /* apm -> lastJobInfoSend = time(NULL); */

    /* get the name of the local host */
    if (gethostname(apm -> myHostname, MAX_STRING_LEN) < 0) {
      strcpy(apm -> myHostname, "unknown");
      logger(WARNING,  "Could not find the local hostname");
    } else {
      apm -> myHostname[MAX_STRING_LEN - 1] = 0;
    }


    /* get the names of the network interfaces */
    ret = procutils_getNetworkInterfaces(&apm -> nInterfaces, 
					 apm -> interfaceNames);
    if (ret != RET_SUCCESS)
      apm -> nInterfaces = 0;

    /* get the IPs of the machine */
    apm -> numIPs = 0; havePublicIP = FALSE;
    strcpy(apm -> myIP, "unknown");
    
    sockd = socket(PF_INET, SOCK_STREAM, 0);
    if(sockd < 0){
      logger(WARNING, "Could not obtain local IP addresses");
    } else {
      for (i = 0; i < apm -> nInterfaces; i++) {
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, apm -> interfaceNames[i], sizeof(ifr.ifr_name) - 1); 
	if(ioctl(sockd, SIOCGIFADDR, &ifr)<0)
	  continue;
	memcpy(ip, ifr.ifr_addr.sa_data+2, 4);
	strcpy(tmp_s, inet_ntoa(*(struct in_addr *)ip));
	if (strcmp(tmp_s, "127.0.0.1") != 0 && !havePublicIP) {
	  strcpy(apm -> myIP, tmp_s);
	  if (!isPrivateAddress(tmp_s))
	    havePublicIP = TRUE;
	}
	strcpy(apm -> allMyIPs[apm -> numIPs], tmp_s);
	apm -> numIPs++;

      }
    }
    
    /* another method to get the IPs */
    /*
    if ((hptr = gethostbyname(apm -> myHostname))!= NULL) {
      i = 0;
      // get from the list the first address (which is not a loopback one)
      while ((hptr -> h_addr_list)[i] != NULL) {
	memcpy(&(addr.s_addr), (hptr -> h_addr_list)[i], 4);
	s = inet_ntoa(addr);
	strcpy(apm -> allMyIPs[apm -> numIPs], s);
	apm -> numIPs++;
	if (strcmp(s, "127.0.0.1") != 0 && !havePublicIP) {
	  strcpy(apm -> myIP, s);
	  if (!isPrivateAddress(s))
	    havePublicIP = TRUE;
	}
	i++;
      }
    }
    */

    apm -> clusterName = strdup("ApMon_UserSend");
    apm -> nodeName = strdup(apm -> myHostname);

    apm -> sysMonCluster = strdup("ApMon_SysMon");
    apm -> sysMonNode = strdup(apm -> myHostname);    

    apm -> prvTime = 0;
    apm -> prvSent = 0;
    apm -> prvDrop = 0;
    apm -> crtTime = 0;
    apm -> crtSent = 0;
    apm -> crtDrop = 0;
    apm -> hWeight = exp(-5.0/60.0);

    srand(time(NULL));

    /* allocate memory for the internal arrays */
    apm -> buf = (char *)malloc(MAX_DGRAM_SIZE);
    if (apm -> buf == NULL)
      return NULL;
    apm -> dgramSize = 0;

    ret = apMon_initSocket(apm);
    if (ret < 0) { 
      return NULL;  
    }

    /* initialize the sender ID and the sequence number */
    apm -> instance_id = rand();
    apm -> seq_nr = 0;
  }
  else
    apm = apm_orig;
     
  if (destAddresses == NULL || destPorts == NULL || nDestinations == 0) {
    logger(WARNING, "No destination hosts specified");
    return NULL;
  }


  /* put the destination addresses, ports & passwords in some temporary
     buffers (because we don't want to lock mutex while making DNS
     requests)
  */
  tmpNDestinations = 0;
  tmpPorts = (int *)malloc(nDestinations * sizeof(int));
  tmpAddresses = (char **)malloc(nDestinations * sizeof(char *));
  tmpPasswds = (char **)malloc(nDestinations * sizeof(char *));
  if (tmpPorts == NULL || tmpAddresses == NULL || 
      tmpPasswds == NULL) {
    logger(FATAL, "Error allocating memory"); 
    return NULL;
  }

  for (i = 0; i < nDestinations; i++) {
    ipAddr = findIP(destAddresses[i]);
    if (ipAddr == NULL)
      continue;

    /* make sure this address is not already in the list */
    found = 0;
    for (j = 0; j < tmpNDestinations; j++) {
      if (!strcmp(ipAddr, tmpAddresses[j])) {
	found = 1;
	break;
      }
    }

    /* add the address to the list */
    if (!found) {
      tmpAddresses[tmpNDestinations] = ipAddr;
      tmpPorts[tmpNDestinations] = destPorts[i];
      tmpPasswds[tmpNDestinations] = strdup(destPasswds[i]);

      sprintf(logmsg, "Added destination host: %s  - port %d\n", 
	     tmpAddresses[tmpNDestinations],
	     tmpPorts[tmpNDestinations]);
      logger(INFO, logmsg);

      tmpNDestinations++;
    }
  }
  
  if (tmpNDestinations == 0) {
    logger(FATAL, "No destination hosts specified. Error initializing ApMon");
    return NULL;
  }

  pthread_mutex_lock(&apm -> mutex);
  if (!firstTime)
      apMon_freeConf(apm);
  apm -> nDestinations = tmpNDestinations;
  apm -> destAddresses = tmpAddresses;
  apm -> destPorts = tmpPorts;
  apm -> destPasswds = tmpPasswds;
  pthread_mutex_unlock(&apm -> mutex);
  //  }  TODO if
  
  /* copy the monitoring settings temporarily kept in the mconf object */
  pthread_mutex_lock(&apm -> mutexBack);
  apMon_copyMonSettings(apm, mconf);
  pthread_mutex_unlock(&apm -> mutexBack);

  /* start job/system monitoring according to these settings */
  apMon_setJobMonitoring(apm, apm -> jobMonitoring, apm -> jobMonitorInterval);
  apMon_setSysMonitoring(apm, apm -> sysMonitoring, apm -> sysMonitorInterval);
  apMon_setGenMonitoring(apm, apm -> genMonitoring, apm -> genMonitorIntervals);
  apMon_setConfRecheck(apm, apm -> confCheck, apm -> recheckInterval);

  /* return the new object or the one given as parameter, modified */
  return apm;
}

void apMon_free(ApMon *apm) {
  int i;

  if (apm -> bkThreadStarted) {
    if (apMon_getJobMonitoring(apm)) {
      /* send a datagram with job monitoring information which covers
	 the last time interval */
      apMon_sendJobInfo(apm);
    }
  }

  pthread_mutex_lock(&apm -> mutexBack);
  apMon_setBackgroundThread(apm, FALSE);
  pthread_mutex_unlock(&apm -> mutexBack);

  pthread_mutex_destroy(&apm -> mutex);
  pthread_mutex_destroy(&apm -> mutexBack);
  pthread_mutex_destroy(&apm -> mutexCond);
  pthread_cond_destroy(&apm -> confChangedCond);

  free(apm -> clusterName);
  free(apm -> nodeName);
  free(apm -> sysMonCluster); free(apm -> sysMonNode);
  free(apm -> monJobs);
 
  apMon_freeConf(apm);
 
  for (i = 0; i < apm -> nSysMonitorParams; i++)
    free(apm -> sysMonitorParams[i]);

  for (i = 0; i < apm -> nGenMonitorParams; i++)
    free(apm -> genMonitorParams[i]);

  for (i = 0; i < apm -> nJobMonitorParams; i++)
    free(apm -> jobMonitorParams[i]);

  free(apm -> initSource);
  
  free(apm -> buf);
  close(apm -> sockfd);
  free(apm);
}

void apMon_freeConf(ApMon *apm) {
  int i;
  freeMat(apm -> destAddresses, apm -> nDestinations);
  freeMat(apm -> destPasswds, apm -> nDestinations);
  free(apm -> destPorts);

  for (i = 0; i < apm -> confURLs.nConfURLs; i++) {
      free(apm -> confURLs.vURLs[i]);
      free(apm -> confURLs.lastModifURLs[i]);
  }
}

int apMon_sendParameters(ApMon *apm, char *clusterName, char *nodeName,
	       int nParams, char **paramNames, int *valueTypes, 
			 char **paramValues) {
  return apMon_sendTimedParameters(apm, clusterName, nodeName, nParams, 
				   paramNames, valueTypes, paramValues, -1);
}


int apMon_sendTimedParameters(ApMon *apm, char *clusterName, char *nodeName,
	       int nParams, char **paramNames, int *valueTypes, 
			 char **paramValues, int timestamp) {
  int i, ret, ret1, ret2;
  char buf2[MAX_HEADER_LENGTH+4], newBuf[MAX_DGRAM_SIZE];
  int buf2Length;
  char *headerTmp;
  char logmsg[150];
  char header[MAX_HEADER_LENGTH] = "v:";
  strcat(header, APMON_VERSION);
  strcat(header, "p:");
 
  pthread_mutex_lock(&apm -> mutex);

  if(!apMon_shouldSend(apm)) {
     pthread_mutex_unlock(&apm -> mutex);
     return RET_NOT_SENT;
  }

  if (clusterName != NULL) { /* don't keep the cached values for cluster name
    and node name */
    free(apm -> clusterName);
     apm -> clusterName = strdup(clusterName);

     if (nodeName != NULL) {  /* the user provided a name */
       free(apm -> nodeName);
       apm -> nodeName = strdup(nodeName);
     }
     else { /* set the node name to the node's hostname */
       free(apm -> nodeName);
       apm -> nodeName = strdup(apm -> myHostname);
     }  /* else */
  } /* if */
     
  if (apm -> clusterName == NULL || apm -> nodeName == NULL) {
    logger(WARNING, "Error initializing cluster name or node name");
    pthread_mutex_unlock(&apm -> mutex);
    return RET_ERROR;
  }


  /* try to encode the parameters */
  ret = apMon_encodeParams(apm, nParams, paramNames, valueTypes, paramValues,
			   timestamp);
  if (ret == RET_ERROR) {
    logger(WARNING, "The send operation was not completed");
    pthread_mutex_unlock(&apm -> mutex);
    return RET_ERROR;
  }

  headerTmp = (char *)malloc(MAX_HEADER_LENGTH * sizeof(char));

  /* for each destination */
  for (i = 0; i < apm -> nDestinations; i++) {
    XDR xdrs;
    struct sockaddr_in destAddr;

    /* initialize the destination address */
    bzero(&destAddr, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(apm -> destPorts[i]);
    inet_pton(AF_INET, apm -> destAddresses[i], &destAddr.sin_addr);
    
     /* add the header (which is different for each destination) */
    strcpy(headerTmp, header);
    strcat(headerTmp, apm -> destPasswds[i]);

     /* initialize the XDR stream to encode the header*/
    xdrmem_create(&xdrs, buf2, MAX_HEADER_LENGTH, XDR_ENCODE); 

    /* encode the header */
    ret = xdr_string(&xdrs, &(headerTmp), strlen(headerTmp) + 1);

    /* add the instance ID and the sequence number */
    ret1 = xdr_int(&xdrs, &(apm -> instance_id));
    ret2 = xdr_int(&xdrs, &(apm -> seq_nr));

    if (!ret || !ret1 || !ret2) {
       logger(WARNING, "XDR encoding error");
       free(headerTmp);
       pthread_mutex_unlock(&apm -> mutex);
       return RET_ERROR;
    }

    /* concatenate the header and the rest of the datagram */
    buf2Length = xdrSize(XDR_STRING, headerTmp) + 2 * xdrSize(XDR_INT32, NULL);
    memcpy(newBuf, buf2, buf2Length);
    memcpy(newBuf + buf2Length, apm -> buf, apm -> dgramSize);

    /* send the buffer */
    ret = sendto(apm -> sockfd, newBuf, apm -> dgramSize + buf2Length, 0, (struct sockaddr *)&destAddr, 
		 sizeof(destAddr));
     
    if (ret == RET_ERROR) {
      sprintf(logmsg, "Error sending data to destination %s ", 
	     apm -> destAddresses[i]);
      logger(WARNING, logmsg);
      close(apm -> sockfd);

      ret = apMon_initSocket(apm);
      if (ret < 0) {
	pthread_mutex_unlock(&apm -> mutex);
	free(headerTmp);
	logger(WARNING, "Error reinitializing socket");
	return RET_ERROR;
      }
    }
    else {
      sprintf(logmsg, "Datagram with size %d, sender ID %d, sequence no %d, sent to %s, containing parameters:\n", 
	     ret, apm -> instance_id, apm -> seq_nr, apm -> destAddresses[i]);
      logger(FINE, logmsg);
      logParameters(FINE, nParams, paramNames, valueTypes, paramValues);
    }
     xdr_destroy(&xdrs);
  }

  apm -> seq_nr = (apm -> seq_nr + 1) % TWO_BILLION;
  free(headerTmp);
  pthread_mutex_unlock(&apm -> mutex);
  return RET_SUCCESS;
}


int apMon_sendParameter(ApMon *apm, char *clusterName, char *nodeName,
			char *paramName, int valueType, char *paramValue) {

  return apMon_sendParameters(apm, clusterName, nodeName, 1, &paramName, 
			      &valueType, &paramValue);
}

int apMon_sendTimedParameter(ApMon *apm, char *clusterName, char *nodeName,
	    char *paramName, int valueType, char *paramValue, int timestamp) {

  return apMon_sendTimedParameters(apm, clusterName, nodeName, 1, &paramName, 
			      &valueType, &paramValue, timestamp);
}

int apMon_sendIntParameter(ApMon *apm, char *clusterName, char *nodeName,
		char *paramName, int paramValue) {
  
  return apMon_sendParameter(apm, clusterName, nodeName, paramName, XDR_INT32, 
		    (char *)&paramValue);
}

int apMon_sendFloatParameter(ApMon *apm, char *clusterName, char *nodeName,
		char *paramName, float paramValue) {
  
  return apMon_sendParameter(apm, clusterName, nodeName, paramName, XDR_REAL32, 
		    (char *)&paramValue);
}

int apMon_sendDoubleParameter(ApMon *apm, char *clusterName, char *nodeName,
		char *paramName, double paramValue) {
  
  return apMon_sendParameter(apm, clusterName, nodeName, paramName, XDR_REAL64, 
		    (char *)&paramValue);
}

int apMon_sendStringParameter(ApMon *apm, char *clusterName, char *nodeName,
		char *paramName, char *paramValue) {
  
  return apMon_sendParameter(apm, clusterName, nodeName, paramName, XDR_STRING, 
		    paramValue);
}


int apMon_encodeParams(ApMon *apm, int nParams, char **paramNames, 
		       int *valueTypes, char **paramValues, int timestamp) {
  XDR xdrs; /* XDR handle. */
  int dgramSize;
  int i, effectiveNParams;;
  char logmsg[100];

  /* count the number of parameters actually sent in the datagram
     (the parameters with a NULL name and the string parameters
     with a NULL value are skipped)
  */
  effectiveNParams = nParams;
  for (i = 0; i < nParams; i++) {
    if (paramNames[i] == NULL || (valueTypes[i] == XDR_STRING && 
				    paramValues[i] == NULL)) {
      effectiveNParams--;
    }
  }
  if (effectiveNParams == 0) {
    logger(WARNING, "[ apMon_encodeParams() ] No valid parameters in datagram, sending aborted");
    return RET_ERROR;
  }

  /*** estimate the length of the send buffer ***/

  /* add the length of the cluster name & node name */
  dgramSize =  xdrSize(XDR_STRING, apm -> clusterName) + 
      xdrSize(XDR_STRING, apm -> nodeName) + xdrSize(XDR_INT32, NULL);
  /* add the lengths for the parameters (name + size + value) */
  for (i = 0; i < nParams; i++)
    dgramSize += xdrSize(XDR_STRING, paramNames[i]) + 
      xdrSize(XDR_INT32, NULL)  +
      xdrSize(valueTypes[i], paramValues[i]);

  /* check that the maximum datagram size is not exceeded */
  if (dgramSize + MAX_HEADER_LENGTH > MAX_DGRAM_SIZE) {
    logger(WARNING, "Maximum datagram size exceeded");
    return RET_ERROR;
  }

  

  /* initialize the XDR stream */
  xdrmem_create(&xdrs, apm -> buf, MAX_DGRAM_SIZE, XDR_ENCODE); 

  /* encode the cluster name, the node name and the number of parameters */
  if (!xdr_string(&xdrs, &(apm -> clusterName), strlen(apm -> clusterName) 
		  + 1))
    return RET_ERROR;

  if (!xdr_string(&xdrs, &(apm -> nodeName), strlen(apm -> nodeName) + 1))
    return RET_ERROR;

  if (!xdr_int(&xdrs, &(effectiveNParams)))
    return RET_ERROR;

  /* encode the parameters */
  for (i = 0; i < nParams; i++) {
    if (paramNames[i] == NULL || (valueTypes[i] == XDR_STRING && 
				    paramValues[i] == NULL)) {
      logger(INFO, "[ apMon_encodeParams() ] NULL parameter name or value - skipping parameter...");
      continue;
    }

    /* parameter name */
    if (!xdr_string(&xdrs, &(paramNames[i]), strlen(paramNames[i]) + 1))
      return RET_ERROR;
    
    /* parameter value type */
    if (!xdr_int(&xdrs, &(valueTypes[i])))  
      return RET_ERROR;

    /* parameter value */
    switch (valueTypes[i]) {
    case XDR_STRING:
      if (!xdr_string(&xdrs, &(paramValues[i]), 
		      strlen(paramValues[i]) + 1))
	return RET_ERROR;
      break;
      /* INT16 is not supported */
/*    case XDR_INT16:  
      if (!xdr_short(&xdrs, (short *)(paramValues[i])))
        return RET_ERROR;
      break;
*/    case XDR_INT32:
      if (!xdr_int(&xdrs, (int *)(paramValues[i])))  
	return RET_ERROR;
      break;
    case XDR_REAL32:
      if (!xdr_float(&xdrs, (float *)(paramValues[i])))
	return RET_ERROR;
      break;
    case XDR_REAL64:
      if (!xdr_double(&xdrs, (double *)(paramValues[i])))
	return RET_ERROR;
      break;
    default:
      sprintf(logmsg,"Don't know how to encode param %s of type %d", 
	       paramNames[i], valueTypes[i]); 
      logger(WARNING, logmsg);
      return RET_ERROR;
    }
  }

  /* encode the timestamp if necessary */
  if (timestamp > 0) {
    if (!xdr_int(&xdrs, &timestamp))  
      return RET_ERROR; 
    dgramSize += xdrSize(XDR_INT32, NULL);    
  }

  apm -> dgramSize = dgramSize;
  xdr_destroy(&xdrs);
  return RET_SUCCESS;
}



void *bkTask(void *param) { 
  struct stat st;
  struct timespec delay;
  int resourceChanged, haveChange, connFailed;
  int nextOp = -1, i, ret;
  int retI;
  ApMon *retP;
  int generalInfoCount;
  time_t crtTime, timeRemained;
  time_t nextRecheck = 0, nextJobInfoSend = 0, nextSysInfoSend = 0;
  ApMon *apm = (ApMon *)param;
  char logmsg[200];

  logger(INFO, "[Starting background thread...]");

  apm -> bkThreadStarted = TRUE;

  crtTime = time(NULL);

  pthread_mutex_lock(&(apm -> mutexBack));
  if (apm -> confCheck) {
    nextRecheck = crtTime + apm -> crtRecheckInterval;
    /*
      printf("###1 crt %ld interv %ld recheck %ld \n", crtTime,
      apm -> crtRecheckInterval, nextRecheck);
    */
    fflush(stdout);
  }
  if (apm -> jobMonitoring)
    nextJobInfoSend = crtTime + apm -> jobMonitorInterval;
  if (apm -> sysMonitoring)
    nextSysInfoSend = crtTime + apm -> sysMonitorInterval;
  pthread_mutex_unlock(&(apm -> mutexBack));
  
  timeRemained = -1;
  generalInfoCount = 0;


  while (1) {
    pthread_mutex_lock(&apm -> mutexBack);
    if (apm -> stopBkThread) {
      pthread_mutex_unlock(&apm -> mutexBack);
      break;
    }
    pthread_mutex_unlock(&apm -> mutexBack);

    crtTime = time(NULL);

    /* printf("### 2 recheck %ld job %ld \n", nextRecheck, nextJobInfoSend); */

    /* determine the next operation that must be performed */
    if (nextRecheck > 0 && (nextJobInfoSend <= 0 || 
			    nextRecheck <= nextJobInfoSend)) {
      if (nextSysInfoSend <= 0 || nextRecheck <= nextSysInfoSend) {
	nextOp = RECHECK_CONF;
	timeRemained = (nextRecheck - crtTime > 0) ? (nextRecheck - crtTime) : 0;
      } else {
	nextOp = SYS_INFO_SEND;
	timeRemained = (nextSysInfoSend - crtTime > 0) ? (nextSysInfoSend - crtTime) : 0;
      }
    } else {
      if (nextJobInfoSend > 0 && (nextSysInfoSend <= 0 || 
				  nextJobInfoSend <= nextSysInfoSend)) {
	nextOp = JOB_INFO_SEND;
	timeRemained = (nextJobInfoSend - crtTime > 0) ? (nextJobInfoSend - crtTime) : 0;
      } else if (nextSysInfoSend > 0) {
	nextOp = SYS_INFO_SEND;
	timeRemained = (nextSysInfoSend - crtTime > 0) ? (nextSysInfoSend - crtTime) : 0;

      }
    }

    if (timeRemained == -1) {
	logger(INFO, "Background thread has no operation to perform...");	
	timeRemained = RECHECK_INTERVAL;
    }

    /* the moment when the next operation should be performed */
    delay.tv_sec = crtTime + timeRemained;
    delay.tv_nsec = 0;

    
    pthread_mutex_lock(&(apm -> mutexBack));

    pthread_mutex_lock(&(apm -> mutexCond));
    /* check for changes in the settings */
    haveChange = FALSE;
    if (apm -> jobMonChanged || apm -> sysMonChanged || apm -> recheckChanged)
      haveChange = TRUE;
    if (apm -> jobMonChanged) {
      if (apm -> jobMonitoring) 
	nextJobInfoSend = crtTime + apm -> jobMonitorInterval;
      else
	nextJobInfoSend = -1;
      apm -> jobMonChanged = FALSE;
    }
    if (apm -> sysMonChanged) {
      if (apm -> sysMonitoring) 
	nextSysInfoSend = crtTime + apm -> sysMonitorInterval;
      else
	nextSysInfoSend = -1;
      apm -> sysMonChanged = FALSE;
    }
    if (apm -> recheckChanged) {
      if (apm -> confCheck) {
	nextRecheck = crtTime + apm -> crtRecheckInterval;
      }
      else
	nextRecheck = -1;
      apm -> recheckChanged = FALSE;
    }
    pthread_mutex_unlock(&(apm -> mutexBack));

    if (haveChange) {
      pthread_mutex_unlock(&(apm -> mutexCond));
      continue;
    }
    
    /* wait until the next operation should be performed or until
       a change in the settings occurs */
    ret = pthread_cond_timedwait(&(apm -> confChangedCond), 
				 &(apm -> mutexCond), &delay);
    pthread_mutex_unlock(&(apm -> mutexCond));

    if (ret == ETIMEDOUT) {
      /* now perform the operation */
      if (nextOp == JOB_INFO_SEND) {
	apMon_sendJobInfo(apm);
	crtTime = time(NULL);
	nextJobInfoSend = crtTime + apMon_getJobMonitorInterval(apm);
      }
      
      if (nextOp == SYS_INFO_SEND) {
	apMon_sendSysInfo(apm);
	if (apMon_getGenMonitoring(apm)) {
	  if (generalInfoCount <= 1)
	    apMon_sendGeneralInfo(apm);
	  generalInfoCount = (generalInfoCount + 1) % apm -> genMonitorIntervals;
	}
	crtTime = time(NULL);
	nextSysInfoSend = crtTime + apMon_getSysMonitorInterval(apm);
      }

      if (nextOp == RECHECK_CONF) {
	resourceChanged = FALSE;
	if (apm -> initType == FILE_INIT) {
	  sprintf(logmsg, "Checking for modifications for file %s", 
		  apm -> initSource);
	  logger(INFO, logmsg);
	  stat(apm -> initSource, &st);
	  if (st.st_mtime > apm -> lastModifFile) {
	    sprintf(logmsg, "File %s modified \n", apm -> initSource);
	    logger(INFO, logmsg);
	    resourceChanged = TRUE;
	  }
	}

	/* check the configuration URLs */
	connFailed = FALSE;
	for (i = 0; i < apm -> confURLs.nConfURLs; i++) {
	  sprintf(logmsg, "[Checking for modifications for URL %s ]", 
		 apm -> confURLs.vURLs[i]);
	  logger(INFO, logmsg);
	  retI = urlModified(apm -> confURLs.vURLs[i], 
			     apm -> confURLs.lastModifURLs[i]);
	  if (retI == TRUE) {
	    sprintf(logmsg, "URL %s modified", apm -> confURLs.vURLs[i]);
	    logger(INFO, logmsg);
	    resourceChanged = TRUE;
	    break;
	  }
	  if (retI == RET_ERROR) {
	    connFailed = TRUE;
	    break;
	  }
	}

	if (resourceChanged && !connFailed) {
	  logger(INFO, "Reloading configuration...");
	  if (apm -> initType == FILE_INIT)
	    retP = apMon_init_f(apm -> initSource, FALSE, apm);
	  else
	    retP = apMon_stringInit_f(apm -> initSource, FALSE, apm);
	}
 
	if (connFailed || (resourceChanged && retP == NULL)) {
	  logger(WARNING, "Error reloading the configuration. Increasing the time interval until the next reload...");
	  apm -> crtRecheckInterval = apm -> recheckInterval * 5;
	}
	else {
	  apm -> crtRecheckInterval = apm -> recheckInterval;
	}
	
	crtTime = time(NULL);
	nextRecheck = crtTime + apm -> crtRecheckInterval;
	/* sleep(apm -> getCrtRecheckInterval()); */
      } 
    } /* if (ret == ETIMEDOUT) */
  }

  return NULL; /* it doesn't matter what we return */
}

int apMon_getConfCheck(ApMon *apm) { return apm -> confCheck; };


long apMon_getRecheckInterval(ApMon *apm) { return apm -> recheckInterval; };


void apMon_setRecheckInterval(ApMon *apm, long val) {
  if (val > 0) {
    apMon_setConfRecheck(apm, TRUE, val);
  }
  else {
    apMon_setConfRecheck(apm, FALSE, val);
  }
}

void apMon_setConfRecheck(ApMon *apm, int confCheck, long interval) {
  char logmsg[100];
  if (apm -> confCheck) {
    sprintf(logmsg, "Enabling configuration reloading (interval %ld)\n", interval);
    logger(INFO, logmsg);
  }

  pthread_mutex_lock(&apm -> mutexBack);
  /*
  if (apm -> initType == DIRECT_INIT) { 
    logger(WARNING, "setConfRecheck(): no configuration file/URL to reload");
    return;
    } */

  apm -> confCheck = confCheck;
  apm -> recheckChanged = TRUE;
  if (confCheck) {
    if (interval > 0) {
      apm -> recheckInterval = interval;
      apm -> crtRecheckInterval = interval;
    } else {
      apm -> recheckInterval = RECHECK_INTERVAL;
      apm -> crtRecheckInterval = RECHECK_INTERVAL;
    }
    apMon_setBackgroundThread(apm, TRUE);
  }
  else {
    if (apm -> jobMonitoring == FALSE && apm -> sysMonitoring == FALSE)
      apMon_setBackgroundThread(apm, FALSE);
  }
  pthread_mutex_unlock(&apm -> mutexBack);
    
}  

void apMon_setConfRecheck_d(ApMon *apm, int confRecheck) {
  apMon_setConfRecheck(apm, confRecheck, RECHECK_INTERVAL);
}

void apMon_setJobMonitoring(ApMon *apm, int jobMonitoring, long interval) {
  char logmsg[100];
  if (jobMonitoring) {
    sprintf(logmsg, "Enabling job monitoring, time interval %ld s...", interval);
    logger(INFO, logmsg);
  } else
    logger(INFO, "Disabling job monitoring...");

  pthread_mutex_lock(&apm -> mutexBack);
  apm -> jobMonitoring = jobMonitoring;
  apm -> jobMonChanged = TRUE;
  if (jobMonitoring == TRUE) {
    if (interval > 0)
      apm -> jobMonitorInterval = interval;
    else
      apm -> jobMonitorInterval = JOB_MONITOR_INTERVAL;
    apMon_setBackgroundThread(apm, TRUE);
  } else {
    /* disable the background thread if it is not needed anymore */
    if (apm -> sysMonitoring == FALSE && apm -> confCheck == FALSE)
      apMon_setBackgroundThread(apm, FALSE);
  }
  pthread_mutex_unlock(&apm -> mutexBack);
}


void apMon_setJobMonitoring_d(ApMon *apm, int jobMonitoring) {
  apMon_setJobMonitoring(apm, jobMonitoring, JOB_MONITOR_INTERVAL);
}

long apMon_getJobMonitorInterval(ApMon *apm) {
    long i = -1;
    pthread_mutex_unlock(&(apm -> mutexBack));
    if (apm -> jobMonitoring)
      i = apm -> jobMonitorInterval;
    pthread_mutex_unlock(&(apm -> mutexBack));
    return i;
}

int apMon_getJobMonitoring(ApMon *apm) {
  int b;
  pthread_mutex_unlock(&(apm -> mutexBack));
  b = apm -> jobMonitoring;
  pthread_mutex_unlock(&(apm -> mutexBack));
  return b;
}

void apMon_setSysMonitoring(ApMon *apm, int sysMonitoring, long interval) {
  char logmsg[100];
  if (sysMonitoring) {
    sprintf(logmsg, "Enabling system monitoring, time interval %ld s...", interval);
    logger(INFO, logmsg);
  } else
    logger(INFO, "Disabling system monitoring...");

  pthread_mutex_lock(&apm -> mutexBack);
  apm -> sysMonitoring = sysMonitoring;
  apm -> sysMonChanged = TRUE;
  if (apm -> sysMonitoring == TRUE) {
    if (interval > 0)
      apm -> sysMonitorInterval = interval;
    else 
      apm -> sysMonitorInterval = SYS_MONITOR_INTERVAL;
    apMon_setBackgroundThread(apm, TRUE);
  }  else {
    /* disable the background thread if it is not needed anymore */
    if (apm -> jobMonitoring == FALSE && apm -> confCheck == FALSE)
      apMon_setBackgroundThread(apm, FALSE);
  }
  pthread_mutex_unlock(&apm -> mutexBack);
}


void apMon_setSysMonitoring_d(ApMon *apm, int sysMonitoring) {
  apMon_setSysMonitoring(apm, sysMonitoring, SYS_MONITOR_INTERVAL);
}

long apMon_getSysMonitorInterval(ApMon *apm) {
  long i = -1;
  pthread_mutex_unlock(&(apm -> mutexBack));
  if (apm -> sysMonitoring)
    i = apm -> sysMonitorInterval;
  pthread_mutex_unlock(&(apm -> mutexBack));
  return i;
}

int getSysMonitoring(ApMon *apm) {
  int b;
  pthread_mutex_unlock(&(apm -> mutexBack));
  b = apm -> sysMonitoring;
  pthread_mutex_unlock(&(apm -> mutexBack));
  return b;
}

void apMon_setGenMonitoring(ApMon *apm, int genMonitoring, int nIntervals) {
  char logmsg[100];
  sprintf(logmsg, "Setting general information monitoring to %s\n", 
	 boolStrings[genMonitoring]);
  logger(INFO, logmsg);
  pthread_mutex_lock(&apm -> mutexBack);
  apm -> genMonitoring = genMonitoring;
  apm -> sysMonChanged = TRUE;
  if (genMonitoring == TRUE) {
    if (nIntervals > 0)
      apm -> genMonitorIntervals = nIntervals;
    else 
      apm -> genMonitorIntervals = GEN_MONITOR_INTERVALS; 
    
    if (apm -> sysMonitoring == FALSE) {
      pthread_mutex_unlock(&apm -> mutexBack);
      apMon_setSysMonitoring_d(apm, TRUE);
      pthread_mutex_lock(&apm -> mutexBack);
    }
  } /* TODO: else check if we can stop the background thread (if no
       system parameters are enabled for monitoring) */
  pthread_mutex_unlock(&apm -> mutexBack);
}

void apMon_setGenMonitoring_d(ApMon *apm, int genMonitoring) {
  apMon_setGenMonitoring(apm, genMonitoring, GEN_MONITOR_INTERVALS);
}

int apMon_getGenMonitoring(ApMon *apm) {
  int b;
  pthread_mutex_unlock(&(apm -> mutexBack));
  b = apm -> genMonitoring;
  pthread_mutex_unlock(&(apm -> mutexBack));
  return b;
}


void apMon_setCrtRecheckInterval(ApMon *apm, long val) {
  pthread_mutex_lock(&apm -> mutexBack);
  apm -> crtRecheckInterval = val;
  pthread_mutex_unlock(&apm -> mutexBack);
}


void apMon_setBackgroundThread(ApMon *apm, int val) {
  /* mutexBack is locked */
  if (val == TRUE) {
    if (!apm -> haveBkThread) {
      pthread_create(&apm -> bkThread, NULL, &bkTask, apm);
      apm -> haveBkThread = TRUE;
    } else {
      pthread_mutex_lock(&apm -> mutexCond);
      pthread_cond_signal(&apm -> confChangedCond);
      pthread_mutex_unlock(&apm -> mutexCond);
    }
  }
  if (val == FALSE) {
    if (apm -> haveBkThread) {
      apm -> stopBkThread = TRUE;
      pthread_mutex_lock(&apm -> mutexCond);
      pthread_cond_signal(&apm -> confChangedCond);
      pthread_mutex_unlock(&apm -> mutexCond);
      logger(INFO, "[Stopping the background thread...]");

      pthread_mutex_unlock(&apm -> mutexBack);
      pthread_join(apm -> bkThread, NULL);
      pthread_mutex_lock(&apm -> mutexBack);
      apm -> haveBkThread = FALSE;
      apm -> bkThreadStarted = FALSE;
      apm -> stopBkThread = FALSE;
    }
    
  }
}

int apMon_addJobToMonitor(ApMon *apm, long pid, char *workdir, 
			  char *clusterName, char *nodeName) {
  MonitoredJob job;
  if (apm -> nMonJobs >= MAX_MONITORED_JOBS)
    return RET_ERROR;

  job.pid = pid;
  if (workdir == NULL) 
    strcpy(job.workdir, "");
  else
    strcpy(job.workdir, workdir);

 if (clusterName == NULL || strlen(clusterName) == 0) 
    strcpy(job.clusterName, "ApMon_JobMon");
  else
    strcpy(job.clusterName, clusterName);
 if (nodeName == NULL || strlen(nodeName) == 0) 
    strcpy(job.nodeName, apm -> myIP);
  else
    strcpy(job.nodeName, nodeName);

  apm -> monJobs[(apm -> nMonJobs)++] = job;
  return RET_SUCCESS;
}

int apMon_removeJobToMonitor(ApMon *apm, long pid) {
  int i, j;

  if (apm -> nMonJobs <= 0)
    return RET_ERROR;
  
  for (i = 0; i < apm -> nMonJobs; i++) { 
    if (apm -> monJobs[i].pid == pid) {
      /* found the job, now remove it */
      for (j = i; j < apm -> nMonJobs - 1; j++)
	apm -> monJobs[j] = apm -> monJobs[j + 1];
      apm -> nMonJobs--;
      return RET_SUCCESS;
    }
  }

  return RET_ERROR; /* the job was not found */
}

void apMon_setSysMonClusterNode(ApMon *apm, char *clusterName, 
				char *nodeName) {
  free (apm -> sysMonCluster); free(apm -> sysMonNode);
  apm -> sysMonCluster = strdup(clusterName);
  apm -> sysMonNode = strdup(nodeName);
}

void apMon_setMaxMsgRate(ApMon *apm, int maxRate) {
  if (maxRate > 0)
    apm -> maxMsgRate  = maxRate;
}

void apMon_errExit(char *msg) {
  logger(FATAL, msg);
  exit(RET_ERROR);
}


int apMon_initSocket(ApMon *apm) {
  int optval1 = 1;
  struct timeval optval2; 
  int ret1, ret2, ret3;

  apm -> sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (apm -> sockfd < 0) { 
    logger(FATAL, "[ apMon_initSocket() ] Error creating socket");
    return RET_ERROR;
  }

  ret1 = setsockopt(apm -> sockfd, SOL_SOCKET, SO_REUSEADDR, 
		    (char *) &optval1, sizeof(optval1));
    
  /* set connection timeout */
  optval2.tv_sec = 20;
  optval2.tv_usec = 0;
  ret2 = setsockopt(apm -> sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &optval2, 
		    sizeof(optval2));
  ret3 = setsockopt(apm -> sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &optval2, 
		    sizeof(optval2));
  if (ret1 != 0 || ret2 != 0 || ret3 != 0) {
    logger(FATAL, "[ initSocket() ] Error initializing socket.");
    return RET_ERROR;
  }

  return RET_SUCCESS;
}

int apMon_parseConf(FILE *fp, int *nDestinations, char **destAddresses, 
		     int *destPorts, char **destPasswds, MonitorConf *mconf) {
  int i, ch;
  char *line = (char *)malloc ((MAX_STRING_LEN1) * sizeof(char));
  char *tmp = NULL; 
  char sbuf[30], *loglevel_s;
  char *pbuf = sbuf;

  /* parse the input file */
  while(fgets(line, MAX_STRING_LEN, fp) != NULL) {

    if (tmp != NULL) {
      free(tmp);
      tmp = NULL;
    }

    line[MAX_STRING_LEN - 1] = 0;
    /* check if the line was too long */
    ch = fgetc(fp); // see if we are at the end of the file
    ungetc(ch, fp);
    //logger(WARNING, line);
    if (line[strlen(line) - 1] != 10 && ch != EOF) {
      /* if the line doesn't end with a \n and we are not at the end
	 of file, the line from the file was longer than MAX_STRING_LEN */
      fclose(fp);
      logger(FATAL, "[ apMon_parseConf() ] Maximum line length exceeded in the conf file");
      return RET_ERROR;
    }

    tmp = trimString(line);
      
    /* skip the blank lines and the comment lines */
    if (strlen(tmp) == 0 || strchr(tmp, '#') == tmp)
      continue;
    
    if (strstr(tmp, "xApMon_loglevel") == tmp) {
      char *tmp2 = tmp;
      strtok_r(tmp2, "= ", &pbuf);
      loglevel_s = strtok_r(NULL, "= ", &pbuf);
      setLogLevel(loglevel_s);
      continue;
    }

    if (strstr(tmp, "xApMon_") == tmp) {
      apMon_parseXApMonLine(mconf, tmp);
      continue;
    }
    
    if (*nDestinations >= MAX_N_DESTINATIONS) {
      free(line); free(tmp); 
      for (i = 0; i < *nDestinations; i++) {
	free(destAddresses[i]);
	free(destPasswds[i]);
      }
      fclose(fp);
      logger(FATAL, "[ parseConf() ] Maximum number of destinations exceeded.");
      return RET_ERROR;
    }

    addToDestinations(tmp, nDestinations, destAddresses, destPorts, 
		      destPasswds);
  }

  if (tmp != NULL)
    free(tmp);
  free(line);
  return RET_SUCCESS;
}

int apMon_shouldSend(ApMon *apm) {

  long now = time(NULL);
  int doSend;
  char msg[200];

  if (now != apm -> crtTime){

    /** new time, update previous counters; */
    apm -> prvSent = apm -> hWeight * apm -> prvSent + (1.0 - apm -> hWeight) 
      * apm -> crtSent / (now - apm -> crtTime);
    apm -> prvTime = apm -> crtTime;
    sprintf(msg, "previously sent: %ld dropped: %ld", apm -> crtSent, 
	    apm -> crtDrop);
    logger(DEBUG, msg);
    /** reset current counter */
    apm -> crtTime = now;
    apm -> crtSent = 0;
    apm -> crtDrop = 0;
    /* printf("\n"); */
  }
		
  /** compute the history */
  int valSent = (int)(apm -> prvSent * apm -> hWeight + apm -> crtSent * 
		      (1.0 - apm -> hWeight));

  doSend = TRUE;
  /** when we should start dropping messages */
  int level = apm -> maxMsgRate - apm -> maxMsgRate / 10;

 
  if (valSent > (apm -> maxMsgRate - level)) {
    int rnd  = rand() % (apm -> maxMsgRate / 10);
    doSend = (rnd <  (apm -> maxMsgRate - valSent));
  }
  /** counting sent and dropped messages */
  if (doSend) {
    (apm -> crtSent)++;
    /* printf("#"); */
  } else {
    (apm -> crtDrop)++;
    /* printf("."); */
  }
  
  return doSend;
}

