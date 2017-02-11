/**
 * \file ApMon.h
 * Declarations for the ApMon structure and for the functions that work
 * with it.
 * ApMon is a helper structure for sending monitoring data to one or
 * more destination hosts that run MonALISA.
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


#ifndef ApMon_h
#define ApMon_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define XDR_STRING  0  /**< Used to code the string data type */
/* #define XDR_INT16   1   Used to code the 2 bytes integer data type (NOT SUPPORTED YET!) */
#define XDR_INT32   2  /**< Used to code the 4 bytes integer data type */
/* #define XDR_INT64   3   Used to code the 8 bytes integer data type  (THE SAME!) */
#define XDR_REAL32  4  /**< Used to code the 4 bytes real data type */
#define XDR_REAL64  5  /**< Used to code the 8 bytes real data type */

#define MAX_DGRAM_SIZE   8192  /**< Maximum UDP datagram size. */
#define MAX_STRING_LEN 512   /**< Maximum string length (for hostnames). */
#define MAX_STRING_LEN1 (MAX_STRING_LEN + 1)
#define RET_SUCCESS  0  /**< Function return value (succes). */
#define RET_ERROR   -1  /**< Function return value (error). */

#define RET_NOT_SENT -3 /**< A datagram was not sent because the number of
			   datagrams that can be sent per second is limited. */

#define MAX_N_DESTINATIONS 30  /**< Maximum number of destinations hosts to
				  which we send the parameters. */

#define DEFAULT_PORT 8884 /**< The default port on which MonALISA listens */
#define MAX_HEADER_LENGTH 45  /**< Maximum header length. */

/** Indicates that the object was initialized from a file. */
#define FILE_INIT  1
/** Indicates that the object was initialized from a list. */
#define LIST_INIT_APMON  2
/** Indicates that the object was initialized directly. */
#define DIRECT_INIT  3
/** Time interval (in sec) at which job monitoring datagrams are sent. */
#define JOB_MONITOR_INTERVAL 20
/** Time interval (in sec) at which system monitoring datagams are sent. */
#define SYS_MONITOR_INTERVAL 20
/** Time interval (in sec) at which the configuration files are checked
    for changes. */
#define RECHECK_INTERVAL 600
/** The number of time intervals at which ApMon sends general system monitoring
 * information (considering the time intervals at which ApMon sends system
 * monitoring information).
 */
#define GEN_MONITOR_INTERVALS 10
/** The maximum number of jobs that can be monitored. */
#define MAX_MONITORED_JOBS 30
/** The maximum number of system parameters. */
#define MAX_SYS_PARAMS 30
/** The maximum number of general system parameters. */
#define MAX_GEN_PARAMS 30
/** The maximum number of job parameters. */
#define MAX_JOB_PARAMS 30
/** The maxim number of mesages per second that will be sent to MonALISA */
#define MAX_MSG_RATE 20

#define NLETTERS 26

#define TWO_BILLION 2000000000

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define APMON_VERSION "2.2.2"

/**
 * Data structure for holding the configuration URLs.
 */
typedef struct ConfURLs {
  /** The number of webpages with configuration data. */
  int nConfURLs;
  /** The addresses of the webpages with configuration data. */
  char *vURLs[MAX_N_DESTINATIONS];
  /** The "Last-Modified" line from the HTTP header for all the
   * configuration webpages. */
  char *lastModifURLs[MAX_N_DESTINATIONS];
} ConfURLs;

/**
 * Data structure which temporarily holds the monitoring configuration variables
 * when the input file/webpage is parsed. See the similar variables
 * from ApMon for details.
 */
typedef struct MonitorConf {
  int autoDisableMonitoring;

  int sysMonitoring, jobMonitoring, genMonitoring;
  int confCheck;

  long jobMonitorInterval, sysMonitorInterval;
  long recheckInterval, crtRecheckInterval;
  int genMonitorIntervals;

  int nSysMonitorParams, nJobMonitorParams, nGenMonitorParams;
  char *sysMonitorParams[30], *genMonitorParams[30], *jobMonitorParams[30];

  int actSysMonitorParams[30],actGenMonitorParams[30], actJobMonitorParams[30];

  int maxMsgRate;

} MonitorConf;


/**
 * Data structure which holds information about a job monitored by ApMon.
 */
typedef struct MonitoredJob {
  long pid;
  /* the job's working dierctory */
  char workdir[MAX_STRING_LEN];
  /* the cluster name that will be included in the monitoring datagrams */
  char clusterName[50]; 
  /* the node name that will be included in the monitoring datagrams */
  char nodeName[50];
} MonitoredJob;

/**
 * Data structure used for sending monitoring data to a MonaLisa module.
 * The data is packed in UDP datagrams, in XDR format.
 * A datagram has the following structure:
 * - header which contains the ApMon version and the password for the MonALISA
 * host and has the following syntax: v:<ApMon_version>p:<password>
 * - cluster name (string)
 * - node name (string)
 * - number of parameters (int)
 * - for each parameter: name (string), value type (int), value
 * <BR>
 * There are two ways to send parameters:
 * 1) a single parameter in a packet (with the function apMon_sendParameter() or
 * with the variants apMon_sendIntegerParameter(), apMon_sendDoubleParameter() etc.)
 * 2) multiple parameters in a packet (with the function apMon_sendParameters())
 * 
 * Since v1.6 ApMon has the xApMon extension, which can be configured to send 
 * periodically, in a background thread, monitoring information regarding 
 * the system and/or some specified jobs.
 */
typedef struct ApMon {
  char *clusterName; /**< The name of the monitored cluster. */
  char *nodeName; /**< The name of the monitored node. */

  /** The cluster name used when sending system monitoring datagrams. */
  char *sysMonCluster; 
  /** The node name used when sending system monitoring datagrams. */
  char *sysMonNode;

  int nDestinations; /**< The number of destinations to send the results to. */
  char **destAddresses; /**< The IP addresses where the results will be sent.*/
  int *destPorts; /**< The ports where the destination hosts listen. */
  char **destPasswds; /**< Passwords for the MonALISA hosts. */

  char *buf; /**< The buffer which holds the message data (encoded in XDR). */
  int dgramSize; /**< The size of the data inside the datagram (the header length is not included) */
  int sockfd; /**< Socket descriptor */

  /** If this flag is TRUE, the configuration file / URLs are periodically
   * rechecked for changes. */
  int confCheck;
  /** The name(s) of the initialization source(s) (file or list). */
  char  *initSource;
  /* The initialization type (from file / list / directly). */
  int initType;

 /** The configuration file and the URLs are checked for changes at
  * this numer of seconds (this value is requested by the user and will
  * be used if no errors appear when reloading the configuration). */
  long recheckInterval;

  /** If the configuraion URLs cannot be reloaded, the interval until
   * the next attempt will be increased. This is the actual value
   * (in seconds) of the interval that is used by ApMon.
   */
  long crtRecheckInterval;

 /** Background thread which periodically rechecks the configuration
      and sends monitoring information. */
  pthread_t bkThread;

  /** Used to protect the general ApMon data structures. */
  pthread_mutex_t mutex;

  /** Used to protect the variables needed by the background thread. */
  pthread_mutex_t mutexBack;

  /** Used for the condition variable confChangedCond. */
  pthread_mutex_t mutexCond;

  /** Used to notify changes in the monitoring configuration. */
  pthread_cond_t confChangedCond;


 /** These flags indicate changes in the monitoring configuration. */
  int recheckChanged, jobMonChanged,sysMonChanged;

  /** If this flag is true, the background thread is created (but
      not necessarily started). */
  int haveBkThread;

  /** If this flag is TRUE, the background thread is started. */
  int bkThreadStarted;

  /** If this flag is true, there was a request to stop the background 
      thread. */
  int stopBkThread;

  /** If this flag is set to TRUE, when the value of a parameter cannot be
   * read from proc/, ApMon will not attempt to include that value in the
   * next datagrams.
   */
  int autoDisableMonitoring;

  /** If this flag is TRUE, packets with system information taken from
   * /proc are periodically sent to MonALISA.
   */
  int sysMonitoring;

  /** If this flag is TRUE, packets with job information taken from
   * /proc are periodically sent to MonALISA.
   */
  int jobMonitoring;

 /** If this flag is TRUE, packets with general system information taken from
   * /proc are periodically sent to MonALISA.
   */
  int genMonitoring;

  /** Job/System monitoring information obtained from /proc is sent at these
   * time intervals.
   */
  long jobMonitorInterval, sysMonitorInterval;

  /** General system monitoring information is sent at a time interval equal
   * to genMonitorIntervals * sysMonitorInterval.
   */
  int genMonitorIntervals;

  /** Number of parameters that can be enabled/disabled by the user in
   * the system/job/general monitoring datagrams.
   */
  int nSysMonitorParams, nJobMonitorParams, nGenMonitorParams;

  /** The names of the parameters that can be enabled/disabled by the user in
   * the system/job/general monitoring datagrams.
   */
  char *sysMonitorParams[30], *genMonitorParams[30], *jobMonitorParams[30];

  /** Arrays of flags that specifiy the active monitoring parameters (the
   * ones that are sent in the datagams).
   */
  int actSysMonitorParams[30],actGenMonitorParams[30], actJobMonitorParams[30];

  ConfURLs confURLs;

  /** The number of jobs that will be monitored */
  int nMonJobs;

  /** Array which holds information about the jobs to be monitored. */
  MonitoredJob *monJobs;

  /** The last time when the configuration file was modified. */
  long lastModifFile;

  /* time_t lastJobInfoSend; */

  /** The name of the user who owns this process. */
  char username[MAX_STRING_LEN];
  /** The group to which the user belongs. */
  char groupname[MAX_STRING_LEN];
  /** The name of the host on which ApMon currently runs. */
  char myHostname[MAX_STRING_LEN];
  /** The main IP address of the host on which ApMon currently runs. */
  char myIP[30];
  /** The number of IP addresses of the host. */
  int numIPs;
  /** A list with all the IP addresses of the host. */
  char allMyIPs[20][30];
  /** The number of CPUs on the machine that runs ApMon. */
  int numCPUs;

  int sysInfo_first;
  /** The moment when the last system monitoring datagram was sent. */
  time_t lastSysInfoSend;
/* The last recorded values for system parameters. */
  double lastSysVals[MAX_SYS_PARAMS];
  /* The current values for the system parameters */
  double currentSysVals[MAX_SYS_PARAMS];
  /* The success/error codes returned by the functions that calculate
     the system parameters */
  int sysRetResults[MAX_SYS_PARAMS];

  /* The current values for the job parameters */
  double currentJobVals[MAX_JOB_PARAMS];
  /* The success/error codes retuprorned by the functions that calculate
     the job parameters */
  int jobRetResults[MAX_JOB_PARAMS];

  /* The current values for the general parameters */
  double currentGenVals[MAX_GEN_PARAMS];
  /* The success/error codes returned by the functions that calculate
     the general parameters */
  int genRetResults[MAX_GEN_PARAMS];

 /* Table which stores the number of processes in each state 
     (R -runnable, S - sleeping etc.) Each entry in the table 
     corresponds to a capital letter. */
  double currentProcessStates[NLETTERS];

  /* CPU information: */
  char cpuVendor[100];
  char cpuFamily[100];
  char cpuModel[100];
  char cpuModelName[200];

  /** The names of the network interfaces. */
  char interfaceNames[20][20];
  /** The number of network interfaces. */
  int nInterfaces;
  /** The total number of bytes sent through each interface, when the
     previous system monitoring datagram was sent. */
  double lastBytesSent[20];
 /** The total number of bytes received through each interface, when the
     previous system monitoring datagram was sent. */
  double lastBytesReceived[20];
  /** The total number of network errors for each interface, when the
     previous system monitoring datagram was sent. */
  double lastNetErrs[20];
  /** The current values for the net_in, net_out, net_errs parameters */
  double *currentNetIn, *currentNetOut, *currentNetErrs;
  /** The number of open TCP, UDP, ICM and Unix sockets. */
  double currentNSockets[4];
  /** The number of TCP sockets in each possible state (ESTABLISHED, 
      LISTEN, ...) */
  double currentSocketsTCP[20];
  /** Table that associates the names of the TCP sockets states with the
      symbolic constants. */
  char *socketStatesMapTCP[20];  

  /* don't allow a user to send more than MAX_MSG messages per second, in average */
  int maxMsgRate;
  long prvTime;
  double prvSent;
  double prvDrop;
  long crtTime;
  long crtSent;
  long crtDrop;
  double hWeight;

  /** Random number that identifies this instance of ApMon. */
  int instance_id;
  /** Sequence number for the packets that are sent to MonALISA.
      MonALISA v 1.4.10 or newer is able to verify if there were 
      lost packets. */
  int seq_nr;

} ApMon;


/* ============= Initialization & Cleanup functions ================= */

/**
 * Initializes an ApMon data structure.
 * @param filename The name of the file which contains the addresses and
 * the ports of the destination hosts (see README for details about
 * the structure of this file). It can also contain URLs from where the
 * hostnames and prots can be read.
 * @return An initialized ApMon structure.
 */
ApMon* apMon_init(char *filename);

/**
 * Initializes an ApMon data structure from a string. The string contains
 * a list of hostnames (and optional, ports and passwords) separated by
 * commas. It can also contain URLs, like the configuration file.
 * Example: "rb.rogrid.pub.ro:8884,ui.rogrid.pub.ro mypassword,http://x.y.z/dest.conf"
 */
ApMon *apMon_stringInit(char *destinationsList);

/**
 * Initializes an ApMon data structure, using arrays instead of a file.
 * @param nDestinations The number of destination hosts where the results will
 * be sent.
 * @param destAddresses Array that contains the hostnames or IP addresses
 * of the destination hosts.
 * @param destPorts The ports where the MonaLisa modules listen on the
 * destination hosts.
 * @param destPasswds The passwords for the MonALISA hosts.
 */
ApMon *apMon_arrayInit(int nDestinations, char **destAddresses,
		       int *destPorts, char **destPasswds);


/**
 * Frees the memory for a ApMon data structure. Must be called when the
 * structure is not necessary anymore.
 * @param apm Pointer to the ApMon structure to be freed.
 */
void apMon_free(ApMon *apm);

/**
 * Sends a parameter and its value to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored. If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param valueType The value type of the parameter. Can be one of the
 * constants XDR_INT32 (integer), XDR_REAL32 (float), XDR_REAL64 (double),
 * XDR_STRING (null-terminated string).
 * @param paramValue Pointer to the value of the parameter.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendParameter(ApMon *apm, char *clusterName, char *nodeName,
	       char *paramName, int valueType, char *paramValue);

/**
 * Sends a parameter and its value to the MonALISA module, together with a 
 * timestamp.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored. If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param valueType The value type of the parameter. Can be one of the
 * constants XDR_INT32 (integer), XDR_REAL32 (float), XDR_REAL64 (double),
 * XDR_STRING (null-terminated string).
 * @param paramValue Pointer to the value of the parameter.
 * @param timestamp The associated timestamp (in seconds).
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendTimedParameter(ApMon *apm, char *clusterName, char *nodeName,
	      char *paramName, int valueType, char *paramValue, int timestamp);

/**
 * Sends an integer parameter and its value to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored. If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param paramValue The value of the parameter.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendIntParameter(ApMon *apm, char *clusterName, char *nodeName,
	       char *paramName, int paramValue);

/**
 * Sends a parameter of type float and its value to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored. If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param paramValue The value of the parameter.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendFloatParameter(ApMon *apm, char *clusterName, char *nodeName,
	       char *paramName, float paramValue);

/**
 * Sends a parameter of type double and its value to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored.  If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param paramValue The value of the parameter.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendDoubleParameter(ApMon *apm, char *clusterName, char *nodeName,
	       char *paramName, double paramValue);

/**
 * Sends a parameter of type string and its value to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored.  If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param paramName The name of the parameter.
 * @param paramValue The value of the parameter.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendStringParameter(ApMon *apm, char *clusterName, char *nodeName,
	       char *paramName, char *paramValue);


/**
 * Sends a set of parameters and their values to the MonALISA module.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored.  If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param nParams The number of parameters to be sent.
 * @param paramNames Array with the parameter names.
 * @param valueTypes Array with the value types represented as integers.
 * @param paramValue Array with the parameter values.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendParameters(ApMon *apm, char *clusterName, char *nodeName,
	       int nParams, char **paramNames, int *valueTypes, 
			 char **paramValues);

/**
 * Sends a set of parameters and their values to the MonALISA module, 
 * together with a timestamp.
 * @param apm Pointer to the ApMon data structure.
 * @param clusterName The name of the cluster that is monitored.  If it is
 * NULL, we keep the same cluster and node name as in the previous datagram.
 * @param nodeName The name of the node from the cluster from which the
 * value was taken.
 * @param nParams The number of parameters to be sent.
 * @param paramNames Array with the parameter names.
 * @param valueTypes Array with the value types represented as integers.
 * @param paramValue Array with the parameter values.
 * @param timestamp The timestamp (in seconds) associated with the data.
 * @return RET_SUCCESS (0) on success, RET_ERROR (-1) if an error occured,
 * RET_NOT_SENT (-3) if the message was not sent because the maximum
 * number of messages per second was exceeded.
 */
int apMon_sendTimedParameters(ApMon *apm, char *clusterName, char *nodeName,
	       int nParams, char **paramNames, int *valueTypes, 
			 char **paramValues, int timestamp);


/**
 * Returns the value of the confCheck flag. If it is TRUE, the 
 * configuration file and/or the URLs are periodically checked for
 * modifications.
 */
int apMon_getConfCheck(ApMon *apm);

/**
 * Returns the value of the time interval (in seconds) between two recheck 
 * operations for the configuration files.
 * If error(s) appear when reloading the configuration, the actual interval 
 *  will be increased (transparently for the user).
 */
long apMon_getRecheckInterval(ApMon *apm);

/**
 * Sets the value of the time interval (in seconds) between two recheck 
 * operations for the configuration files. The default value is 5min.
 * If the value is negative, the configuration rechecking is turned off.
 * If error(s) appear when reloading the configuration, the actual interval will
 * be increased (transparently for the user).
 */
void apMon_setRecheckInterval(ApMon *apm, long val);


/** Enables/disables the periodical check for changes in the configuration
 * files/URLs. 
 * @param confRecheck If it is TRUE (1), the periodical checking is enabled.
 * @param interval The time interval at which the verifications are done. If 
 * it is negative, a default value will be used.
 */
void apMon_setConfRecheck(ApMon *apm, int confRecheck, long interval);

/** Enables/disables the periodical check for changes in the configuration
 * files/URLs. If enabled, the verifications will be done at the default 
 * time interval.
 */  
void apMon_setConfRecheck_d(ApMon *apm, int confRecheck);

/** Enables/disables the periodical sending of datagrams with job monitoring
 * information.
 * @param jobMonitoring If it is TRUE, the job monitoring is enabled
 * @param interval The time interval at which the datagrams are sent. If 
 * it is negative, a default value will be used.
 */ 
void apMon_setJobMonitoring(ApMon *apm, int jobMonitoring, long interval);

/** Enables/disables the job monitoring. If the job monitoring is enabled, 
 * the datagrams will be sent at the default time interval.
 */  
void apMon_setJobMonitoring_d(ApMon *apm, int jobMonitoring);

/** Returns the interval at which job monitoring datagrams are sent. If the
 * job monitoring is disabled, returns -1.
 */
long apMon_getJobMonitorInterval(ApMon *apm);

/** Returns TRUE if the job monitoring is enabled, and FALSE otherwise. */
int apMon_getJobMonitoring(ApMon *apm);

/** Enables/disables the periodical sending of datagrams with system
 * monitoring information.
 * @param sysMonitoring If it is TRUE, the system monitoring is enabled
 * @param interval The time interval at which the datagrams are sent. If 
 * it is negative, a default value will be used.
 */ 
void apMon_setSysMonitoring(ApMon *apm, int sysMonitoring, long interval); 

/** Enables/disables the system monitoring. If the system monitoring is 
 * enabled, the datagrams will be sent at the default time interval.
 */  
void apMon_setSysMonitoring_d(ApMon *apm, int sysMonitoring);

/** Returns the interval at which system monitoring datagrams are sent. If 
 * the job monitoring is disabled, returns -1.
 */
long apMon_getSysMonitorInterval(ApMon *apm);

/** Returns TRUE if the system monitoring is enabled, and FALSE otherwise. */
int getSysMonitoring(ApMon *apm);

/** Enables/disables the periodical sending of datagrams with general system 
 * information.
 * @param genMonitoring If it is TRUE, enables the sending of the datagrams.
 * @param interval The number of time intervals at which the datagrams are 
 * sent (considering the interval for sending system monitoring information).
 * If it is negative, a default value will be used.
 */ 
void apMon_setGenMonitoring(ApMon *apm, int genMonitoring, int nIntervals);

/**Enables/disables the sending of datagrams with general system information.
 * A default value is used for the number of time intervals at which the
 * datagrams are sent.
 */
void apMon_setGenMonitoring_d(ApMon *apm, int genMonitoring);

/** Returns TRUE if the sending of general system information is enabled and
 * FALSE otherwise.
 */
int apMon_getGenMonitoring(ApMon *apm);

/**
 * Adds a new job to the list of the jobs monitored by ApMon.
 * @param apm The ApMon object.
 * @param job The job to be monitored. 
 */
int apMon_addJobToMonitor(ApMon *apm, long pid, char *workdir, char *clusterName,
			  char *nodeName);

/**
 * Removes a job from the list of the jobs monitored by ApMon.
 * @param apm The ApMon object.
 * @param pid The pid of the job to be removed. 
 */
int apMon_removeJobToMonitor(ApMon *apm, long pid);

/** This function is called by the user to set the cluster name and the node 
    name for the system monitoring datagrams.*/
void apMon_setSysMonClusterNode(ApMon *apm, char *clusterName, char *nodeName);

/**
 * This sets the maxim number of messages that are send to MonALISA in one second.
 * Default, this number is 50.
 */ 
void apMon_setMaxMsgRate(ApMon *apm, int maxRate);

/**
 * Displays an error message and exits with -1 as return value.
 * @param msg The message to be displayed.
 */
void apMon_errExit(char *msg);
#endif








