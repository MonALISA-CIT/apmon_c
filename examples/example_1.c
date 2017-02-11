/**
 * \file example_1.c
 * This is a simple example for using the ApMon class. 
 * It illustrates the way to send to MonALISA an UDP datagram with a 
 * parameter and its value, using the function sendParameter().
 * The number of datagrams can be specified in the command line (if it is not,
 * the default is 20).
 * The file "destinations_1.conf" contains the addresses of the hosts to which
 * we send the parameters, and also the corresponding ports.
 */ 

#include "ApMon.h"

int main(int argc, char **argv) {
  char *filename = "destinations_1.conf";  
  int nDatagrams = 20;
  ApMon *apm;
  double val = 0;
  int i, ret;

  if (argc ==2)
    nDatagrams = atoi(argv[1]);

  /* set the ApMon loglevel; this can be overriden by the one set in the
     configuration file */
  setLogLevel("WARNING");
      
  /* initialize the ApMon structure */
  apm = apMon_init(filename);
  if (apm == NULL)
    apMon_errExit("\nError initializing the ApMon structure");


  /* for the first datagram sent we specify the cluster name, which will be
     cached and used for the next datagrams; the node name is left NULL, so 
     the local IP will be sent instead) */
  ret = apMon_sendDoubleParameter(apm, "TestCluster1_c", NULL, "my_cpu_load", 
				   val);
  if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
  }

  for (i = 0; i < nDatagrams - 1; i++) {
    /* add a value for the CPU load */
    val += 0.05;
    if (val > 2)
      val = 0;
    printf("Sending %lf for my_cpu_load\n", val);

    /* use the wrapper function with simplified syntax */
    /* (the node name is left NULL, so the local IP will be sent instead) */
    ret = apMon_sendDoubleParameter(apm, "MyCluster_1a_c", NULL, "my_cpu_load", 
				    val);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending result");
    }
   sleep(1);
  }

  apMon_free(apm);
  return 0;
}
