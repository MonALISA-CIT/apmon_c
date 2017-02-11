/**
 * \file example_x1.c
 * This is a simple example for using the ApMon class and the xApMon extension.
 * It illustrates the way to send to MonALISA UDP datagrams with a 
 * parameter and its value, using the function sendParameter(), and the way to 
 * set up job and system monitoring.
 * The file "destinations_x1.conf" contains the addresses of the hosts to which
 * we send the parameters, and also the corresponding ports. The file also
 * contains settings for the job and system monitoring (there is also the 
 * possibility to enable or disable each monitoring parameter separately).
 */
 
#include <stdlib.h> 
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "ApMon.h"

int main(int argc, char **argv) {
  char *filename = "destinations_x1.conf";  
  char *destlist = "http://lcfg.rogrid.pub.ro/~corina/destinations_x1.conf, http://cipsm.rogrid.pub.ro/~corina/destinations_x1.conf";
  int nDatagrams = 30;
  ApMon *apm;
  char clusterName[30], workdir[100];
  FILE *fp; 

  double val;
  int i, ret;

  srand(time(NULL));

 /* get the working directory for this job */
  fp = popen("pwd", "r");
  if (fp == NULL) {
    fprintf(stderr, "Error getting the job working directory");
    strcpy(workdir, "");
  } else {
    fscanf(fp, "%s", workdir);
    pclose(fp);
  }

  strcpy(clusterName, "TestCluster_job");

  if (argc ==2)
    nDatagrams = atoi(argv[1]);
 
  /* try two ways to initialize ApMon */
  apm = apMon_init(filename);
  /* apm = apMon_stringInit(destlist); */
  
  if (apm == NULL)
    apMon_errExit("\nError initializing the ApMon structure");

  apMon_addJobToMonitor(apm, getpid(), workdir, clusterName, NULL);

  /* check the configuration file for changes */
  apMon_setRecheckInterval(apm, 60);
  for (i = 0; i < nDatagrams; i++) {
    /* add a value for the CPU load (random between 0 and 2) */
    val = 2 * (double)rand() / RAND_MAX;  
    printf("Sending %lf for my_cpu_load\n", val);
    /* use the wrapper function with simplified syntax */
    /* (the node name is left NULL, so the local IP will be sent instead) */
    ret = apMon_sendDoubleParameter(apm, "TestClusterx1_c", NULL, 
				    "my_cpu_load", val);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }
    sleep(1);
    
  } // for
  
  return 0;
}
