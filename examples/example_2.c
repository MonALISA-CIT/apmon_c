/**
 * \file example_2.c
 * This is a simple example for using the ApMon structure. 
 * It illustrates the way to send to MonALISA an UDP datagram with a 
 * parameter and its value, using the sendParameter() and sendTimedParameter()
 *  functions.
 * The number of parameters that will be sent can be specified in the command 
 * line (if it is not, the default is 20). For each parameter value two 
 * datagrams are sent: one with a timestamp and one without a timestamp. For 
 * the latter, the local time at the MonALISA host will be considered.
 */ 

#include <stdlib.h> 
#include <time.h>

#include "ApMon.h"

int main(int argc, char **argv) {
  char *destinationsList = "rb.rogrid.pub.ro password, http://lcfg.rogrid.pub.ro/~corina/destinations_2.conf";  
  int nDatagrams = 20;
  ApMon *apm;
  double val;
  int i, ret, timestamp;

  srand(time(NULL));

  if (argc ==2)
    nDatagrams = atoi(argv[1]);
    
  /* initialize the ApMon structure */
  apm = apMon_stringInit(destinationsList);
  if (apm == NULL)
    apMon_errExit("\nError initializing the ApMon structure");

  apMon_setRecheckInterval(apm, 300);
  for (i = 0; i < nDatagrams; i++) {
    /* add a value for the CPU load (random between 0 and 2) */
    val = 2 * (double)rand() / RAND_MAX;  
    printf("Sending %lf for my_cpu_load\n", val);
    /* use the wrapper function with simplified syntax */
    /* (the node name is left NULL, so the local IP will be sent instead) */
    ret = apMon_sendParameter(apm, "TestCluster2_c", NULL, "my_cpu_load", 
			      XDR_REAL64, (char *)&val);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }

    /* now send the datagram with a timestamp */
    timestamp = time(NULL) - (5 * 3600); /* as if it was sent 5 hours ago */
    ret = apMon_sendTimedParameter(apm, "TestCluster2_c_5", NULL, "my_cpu_load", 
			      XDR_REAL64, (char *)&val, timestamp);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }

    /* test that we can stop the thread which reloads the configuration */    
    if (i == 15)
      apMon_setRecheckInterval(apm, -1);
    sleep(2);
  }

  apMon_free(apm);
  return 0;
}
