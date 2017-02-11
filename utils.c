/**
 * \file utils.c
 * This file contains the declarations of some helper methods for ApMon.
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

#include "ApMon.h"
#include "utils.h"

/* ApMon current log level */
static int loglevel = INFO;
/* for synchronization when logging */
static pthread_mutex_t logger_mutex;
/* indicates whether it is the first time when the logger function is called */
static int firstTime_log = TRUE;
static char *levels[5] = {"FATAL", "WARNING", "INFO", "FINE", "DEBUG"};

int urlModified(char *url, char *lastModified) {
  FILE *tmp_file;
  int lineFound;
  char line[MAX_STRING_LEN1], *ret;
  long mypid = getpid();
  char str1[100], str2[100];
  int retI;
  char temp_filename[30];

  sprintf(temp_filename, "/tmp/temp_file%ld", mypid);

  /* get the HTTP header and put it in a temporary file */
  retI = httpRequest(url, "HEAD", temp_filename);
  if (retI == RET_ERROR)
    return RET_ERROR;

   /* read the header from the temporary file */
  tmp_file = fopen(temp_filename, "rt");
  if (tmp_file == NULL)
    return RET_ERROR;

  /* check if we got the page correctly */
  fgets(line, MAX_STRING_LEN, tmp_file);
  sscanf(line, "%s %s", str1, str2);
  if (atoi(str2) != 200) {
    logger(WARNING, "Error getting the page from the server");
    return RET_ERROR;
  }

  /* look for the "Last-Modified" line */
  lineFound = FALSE;
  while ((ret = fgets(line, MAX_STRING_LEN, tmp_file)) != NULL) {
    if (strstr(line, "Last-Modified") == line) {
      lineFound = TRUE;
      break;
    }
  }
  
  fclose(tmp_file);
  unlink(temp_filename);
  if (lineFound) {
    if (strcmp(line, lastModified) != 0)
      return TRUE;
    else
      return FALSE;
  } else
    /* if the line was not found we must assume the page was modified */
    return TRUE;
}  

int httpRequest(char *url, char *reqType, char *temp_filename) {
  /* the server from which we get the configuration file */
  char hostname[MAX_STRING_LEN]; 
  /* the name of the remote configuration file */
  char filename[MAX_STRING_LEN];
  /* the port on which the server listens (by default 80) */
  int port;
  
  int sd, rc;
  struct sockaddr_in localAddr, servAddr;
  struct hostent *h;
  struct timeval optval;
  char logmsg[100];

  char *request; /* the HTTP request */
 
  int result;

  char buffer[MAX_STRING_LEN]; /* for reading from the socket */
  int totalSize; /* the size of the remote file */
  
  FILE *tmp_file; 

  result = parse_URL(url, hostname, &port, filename);
  if (result == RET_ERROR)
    return RET_ERROR;

  sprintf(logmsg, "Getting configuration from: \n Hostname: %s , Port: %d , Filename: %s\n", 
	 hostname, port, filename);
  logger(INFO, logmsg);
  
  request = (char *)malloc(MAX_STRING_LEN * sizeof(char));
  strcpy(request, reqType);
  strcat(request, " ");

  request = (char *)strcat( request, filename);
  request = (char *)strcat( request, " HTTP/1.0\r\nHOST: ");
  request = (char *)strcat( request, hostname);
  request = (char *)strcat( request, "\r\n\r\n");

  h = gethostbyname(hostname);
  if(h==NULL) {
    sprintf(logmsg, "Unknown host: %s ", hostname);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }

  servAddr.sin_family = h->h_addrtype;
  memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
  servAddr.sin_port = htons(port); /* (LOCAL_SERVER_PORT); */

  /* create socket */
  sd = socket(AF_INET, SOCK_STREAM, 0);
  if(sd<0) {
    logger(WARNING, "Cannot open socket");
    return RET_ERROR;
  }

  /* set connection timeout */
  optval.tv_sec = 10;
  optval.tv_usec = 0;
  setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char *) &optval, 
			sizeof(optval));
  setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *) &optval, 
			sizeof(optval));

  localAddr.sin_family = AF_INET;
  localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  localAddr.sin_port = htons(0);
  
  /*
  rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
  if(rc<0) {
    sprintf(logmsg,"%s: cannot bind port TCP %u", url,port); 
    logger(WARNING, logmsg);
    return RET_ERROR;
  }
  */
				
  /* connect to the server */
  rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
  if(rc<0) {
    sprintf(logmsg, "Cannot connect to server");
    logger(WARNING, logmsg);
    return RET_ERROR;
  }

  /* send the GET request */
  rc = send(sd, request, strlen(request), 0);
  if(rc<0) {  
    close(sd);
    logger(WARNING, "Cannot send data to server");
    return RET_ERROR;
  }

  /* read the response and put it in a temporary file */
  tmp_file = fopen(temp_filename, "wb");
  if (tmp_file == NULL) { 
    sprintf(logmsg, "Unable to open temporary file %s", temp_filename);
    logger(WARNING, logmsg);
    return RET_ERROR;
  }

  rc = 0, totalSize = 0;
  do {
    memset(buffer,0x0,MAX_STRING_LEN);    /* init line */
    /* rc = read(sd, buffer, MAX_STRING_LEN); */
    rc = recv(sd, buffer, MAX_STRING_LEN, 0);
    if( rc > 0) { 
      fwrite(buffer, rc, 1, tmp_file);
      totalSize +=rc;
    }
  }while(rc>0);

  sprintf(logmsg, "Received response from  %s, response size is %d bytes \n", 
	  hostname, totalSize);
  logger(INFO, logmsg);

  close(sd);
  fclose(tmp_file);
  free(request);
  return RET_SUCCESS;
}

int xdrSize(int type, char *value) {
  int size;
  
  switch (type) {
/*  case XDR_INT16: (not supported) */
  case XDR_INT32:
  case XDR_REAL32:
    return 4;
/*  case XDR_INT64:  (not supported) */
  case XDR_REAL64:
    return 8;
  case XDR_STRING:
    /* XDR adds 4 bytes to hold the length of the string */
    size = strlen(value) + 4;
    /* the length of the XDR representation must be a multiple of 4,
       so there might be some extra bytes added*/
    if (size % 4 != 0)
      size += (4 - size % 4);
    return size;
  }
  
  return RET_ERROR;
}

int sizeEval(int type, char *value) {
  
  switch (type) {
/*  case XDR_INT16: */
  case XDR_INT32:
  case XDR_REAL32:
    return 4;
/*  case XDR_INT64: */
  case XDR_REAL64:
    return 8;
  case XDR_STRING:
    return (strlen(value) + 1);
  }
  
  return RET_ERROR;
}

char *findIP(char *address) {
  int isIP = 1;
  char *destIP, *s, logmsg[100];
  struct in_addr addr;
  int j;

  for (j = 0; j < strlen(address); j++)
      if (isalpha(address[j])) {
	/* if we found a letter, this is not an IP address */
	isIP = 0;
	break;
      }
     
    if (!isIP) {  /* the user provided a hostname, find the IP */
      struct hostent *he = gethostbyname(address);
      if (he == NULL) {
	sprintf(logmsg, "Not a valid destination address - %s", address);
	logger(WARNING, logmsg);
	return NULL;
      }
      j = 0;
      /* get from the list the first IP address 
	 (which is not a loopback one) */
      while ((he -> h_addr_list)[j] != NULL) {
	memcpy(&(addr.s_addr), he -> h_addr, 4);
	s = inet_ntoa(addr);
	if (strcmp(s, "127.0.0.1") != 0) {
	  destIP = strdup(s);
	  break;
	}
	j++;
      }
    
    } else /* the string was an IP address */
      destIP = strdup(address);
    
    return destIP;
}

int parse_URL(char *url, char *hostname, int *port, char *identifier) {
    char protocol[MAX_STRING_LEN], scratch[MAX_STRING_LEN], *ptr=0, *nptr=0;
    char logmsg[100];

    strcpy(scratch, url);
    ptr = (char *)strchr(scratch, ':');
    if (!ptr)
    {
	logger(WARNING, "Wrong url: no protocol specified");	
	return RET_ERROR;
    }
    strcpy(ptr, "\0");
    strcpy(protocol, scratch);
    if (strcmp(protocol, "http")) {
	sprintf(logmsg, "Wrong protocol: %s", protocol);
	logger(WARNING, logmsg);
	return RET_ERROR;
    }

    strcpy(scratch, url);
    ptr = (char *)strstr(scratch, "//");
    if (!ptr) {
	logger(WARNING, "Wrong url: no server specified");
	return RET_ERROR;
    }
    ptr += 2;

    strcpy(hostname, ptr);
    nptr = (char *)strchr(ptr, ':');
    if (!nptr) {
	*port = 80; /* use the default HTTP port number */
	nptr = (char *)strchr(hostname, '/');
    } else {	
	sscanf(nptr, ":%d", port);
	nptr = (char *)strchr(hostname, ':');
    }

    if (nptr)
      *nptr = '\0';

    nptr = (char *)strchr(ptr, '/');
    if (!nptr) {
	logger(WARNING, "Wrong url: no file specified");
	return RET_ERROR;
    }
    strcpy(identifier, nptr);
    return RET_SUCCESS;
}

void freeMat(char **mat, int nRows) {
  int i;
  for (i = 0; i < nRows; i++)
    free(mat[i]);
  free(mat);
}

char *trimString(char *s) {
  unsigned int i, j, firstpos, lastpos;
  char *ret = (char *)malloc((strlen(s) + 1) * sizeof(char));
  j = 0;

  /* find the position of the first non-space character in the string */
  for (i = 0; i < strlen(s); i++)
    if (!isspace(s[i]))
      break;
  firstpos = i; 

  if (firstpos == strlen(s)) {
    ret[0] = 0;
    return ret;
  }

  /* find the position of the last non-space character in the string */
  for (i = strlen(s) - 1; i >= 0; i--)
    if (!isspace(s[i]))
	break;
  lastpos = i; 

  for (i = firstpos; i <= lastpos; i++)
      ret[j++] = s[i];

  ret[j++] = 0;
  return ret;
}

int isPrivateAddress(char *addr) {
  char *s1, *s2;
  int n1, n2;
  char tmp[MAX_STRING_LEN], buf[MAX_STRING_LEN];
  char *pbuf = buf;

  strcpy(tmp, addr);
  s1 = strtok_r(tmp,".", &pbuf); 
  n1 = atoi(s1);

  s2 = strtok_r(NULL, ".", &pbuf);
  n2 = atoi(s2);

  if (n1 == 10)
    return TRUE;
  if (n1 == 172 && n2 >= 16 && n2 <= 31)
    return TRUE;
  if (n1 == 192 && n2 == 168)
    return TRUE;

  return TRUE;
}

void logParameters(int level, int nParams, char **paramNames, 
		     int *valueTypes, char **paramValues) {
  int i;
  char logmsg[200], val[100];
  char typeNames[][15] = {"XDR_STRING", "", "XDR_INT32", "", "XDR_REAL32", 
		 "XDR_REAL64"};

  for (i = 0; i < nParams; i++) {
    sprintf(logmsg, "%s (%s) ", paramNames[i], typeNames[valueTypes[i]]);
    switch(valueTypes[i]) {
    case XDR_STRING:
      sprintf(val, "%s", paramValues[i]);
      break;
    case XDR_INT32:
      sprintf(val, "%d", *(int *)paramValues[i]);
      break;
    case XDR_REAL32:
      sprintf(val, "%f", *(float *)paramValues[i]);
      break;
    case XDR_REAL64:
      sprintf(val, "%lf", *(double *)(paramValues[i]));
      break;  
    }
    strcat(logmsg, val);
    logger(level, logmsg);
  }
}

int getVectIndex(char *item, char **vect, int vectDim) {
  int i;

  for (i = 0; i < vectDim; i++)
    if (strcmp(item, vect[i]) == 0)
      return i;
  return -1;
}
  

void logger(int msgLevel, const char *msg) {
  char time_s[30], cbuf[50];
  int len;
  long crtTime = time(NULL);
  
  strcpy(time_s, ctime_r(&crtTime, cbuf)); 
  len = strlen(time_s); time_s[len - 1] = 0;

  if (firstTime_log) {
    pthread_mutex_init(&logger_mutex, NULL);
    firstTime_log = FALSE;
  }
  
  /* TODO: solve synchronization problem */
  /*  pthread_mutex_lock(&logger_mutex); */
  if (msgLevel >= 0 && msgLevel <= 4) {
    if (msgLevel <= loglevel)
      printf("[%s] [%s] %s\n",time_s, levels[msgLevel], msg);
  } else {
    printf("[WARNING] Invalid logging level %d!\n", msgLevel);
  }

  /* pthread_mutex_unlock(&logger_mutex); */
}

void setLogLevel(char *newLevel_s) {
  int newLevel;
  char logmsg[100];

  pthread_mutex_lock(&logger_mutex);
  for (newLevel = 0; newLevel < 5; newLevel++)
    if (strcmp(newLevel_s, levels[newLevel]) == 0)
      break;

  if (newLevel >= 5) {
    sprintf(logmsg, "Invalid logging level: %s\n", newLevel_s);
    logger(WARNING, logmsg); 
  } else {
    loglevel = newLevel;
    sprintf(logmsg, "Changed the logging level to %s\n",  newLevel_s);
    logger(INFO, logmsg);
  }
  pthread_mutex_unlock(&logger_mutex);
}
