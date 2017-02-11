/**
 * \file example_confgen.c
 * This example illustrates the way ApMon can obtain the configuration 
 * parameters from a servlet or a CGI script.
 */

#include <stdlib.h> 
#include <time.h>

#include "ApMon.h"

int main(int argc, char **argv) {
  char *destinationsList = "http://pcardaab.cern.ch:8888/cgi-bin/ApMonConf?appName=confgen_test"; 
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
#ifdef VERBOSE
    printf("Sending %lf for cpu_load\n", val);
#endif
    /* use the wrapper function with simplified syntax */
    /* (the node name is left NULL, so the local IP will be sent instead) */
    ret = apMon_sendParameter(apm, "TestClusterCG_c", NULL, "cpu_load", 
			      XDR_REAL64, (char *)&val);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }

    /* now send the datagram with a timestamp */
    timestamp = time(NULL) - (5 * 3600); /* as if it was sent 5 hours ago */
    ret = apMon_sendTimedParameter(apm, "TestClusterOldCG_c", NULL, "cpu_load", 
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
