/**
 * \file exampleSend_x2.c
 * This example shows how several jobs can be monitored with ApMon. The user 
 * must provide the PIDs of the jobs to be monitored. In order to find the PID
 * of the jobs we shall parse the output of the ps command. We shall monitor
 * the following applications: the current job, MonALISA and Apache (assuming
 * the last two are currently running).
 * The file "destinations_x2.conf" contains the addresses of the hosts to which
 * we send the parameters, and also the corresponding ports. It also contains
 * lines in which different parameters from the job/system monitoring datagrams
 * can be enabled or disabled.
 */ 
#include <stdlib.h> 
#include <time.h>

#include "ApMon.h"

/** Finds the PID of the parent process for an application, given
 * the name of the application. 
 */
long getAppPid(char *cmd) {
  FILE *fp;
  char buf[1024];
  int found;
  long pid;

  fp = popen("ps afx", "r");
  if (fp == NULL) 
    return -1;

  found = FALSE;
  while (fgets(buf, 1024, fp) != NULL) {
    if (strstr(buf, cmd) != NULL) {
      found = TRUE;
      break;
    }
  }
  pclose(fp);
  if (found == FALSE)
    return -1;

  sscanf(buf, "%ld", &pid);
  return pid;
}

int main(int argc, char **argv) {
  char *filename = "destinations_x2.conf";
  int nDatagrams = 20;
  char *osname = "linux";
  double val;
  int i, val2, ret;
  long pid_ml, pid_a;
  int nParameters = 3;
  char **paramNames, **paramValues;
  int *valueTypes;
  ApMon *apm;

  srand(time(NULL));

  if (argc ==2)
    nDatagrams = atoi(argv[1]);

 /* allocate memory for the arrays */
  paramNames = (char **)malloc(nParameters * sizeof(char *));
  paramValues = (char **)malloc(nParameters * sizeof(char *));
  valueTypes = (int *)malloc(nParameters * sizeof(int));

  /* initialize the parameter names and types */
  paramNames[0] = "my_cpu_load";
  valueTypes[0] = XDR_REAL64;
  paramNames[1] = "my_os_name";
  valueTypes[1] = XDR_STRING;
  paramNames[2] = "my_cpu_idle";
  valueTypes[2] = XDR_INT32;

  /* initialize the pointers to the values */
  /* (the values will change, but the addresses remain the same) */ 
  paramValues[0] = (char *)&val;
  paramValues[1] = osname; 
  paramValues[2] = (char *)&val2;

 /* initialize the ApMon structure */
  apm = apMon_init(filename);
  if (apm == NULL)
    apMon_errExit("\nError initializing the ApMon structure");

  apMon_setJobMonitoring(apm, TRUE, 5);
  apMon_setSysMonitoring(apm, TRUE, 10);
  apMon_setGenMonitoring(apm, TRUE, 100);

  /* monitor this job */
  apMon_addJobToMonitor(apm, getpid(), "", "JobCluster_apmon", NULL);

  /* monitor MonALISA */
  pid_ml = getAppPid("java -DMonaLisa_HOME");
  if (pid_ml != -1)
    apMon_addJobToMonitor(apm, pid_ml, "", "JobCluster_monalisa", NULL);
  else
    fprintf(stderr, "Error obtaining PID for: java -DMonaLisa_HOME\n");

  /* monitor apache */
  pid_a = getAppPid("apache");
  if (pid_a != -1)
    apMon_addJobToMonitor(apm, pid_a, "", "JobCluster_apache", NULL);
  else
    fprintf(stderr, "Error obtaining PID for: apache\n");
  
//  for (i = 0; i < nDatagrams; i++) {
    while (1) {
    /* add a value for the CPU load (random between 0 and 2) */
    val = 2 * (double)rand() / RAND_MAX;  
      printf("Sending %lf for cpu_load\n", val);

      /* add a value for the CPU idle percentage (random between 0 and 50) */
      val2 = (int)(50 * (double)rand() / RAND_MAX);
      printf("Sending %d for my_cpu_idle\n", val2);

      ret = apMon_sendParameters(apm, "TestClusterx2_c", "MyNode2", nParameters, 
			   paramNames, valueTypes, paramValues);

     if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }
      sleep(5);
  } // for
  
  return 0;
}
