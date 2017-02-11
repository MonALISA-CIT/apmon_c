/**
 * \file example_4.cpp
 * This example shows how multiple ApMon objects can be used in the same 
 * program. However, this is not the suggested way to use ApMon; if possible, 
 * it is better to work with a single ApMon object because in this way the
 * network socket and other resources are re-used.
 * The number of times we instantiate an ApMon object can be specified in the 
 * command line (if it is not, the default is 20).
 * The file "destinations_1.conf" contains the addresses of the hosts to which
 * we send the parameters, and also the corresponding ports.
 */ 

#include "ApMon.h"
#include <time.h> 

int main(int argc, char **argv) {
  char *initurl = "http://lcfg.rogrid.pub.ro/~corina/destinations_x1.conf";  
  int nObjects = 20;
  double val = 0;
  int i, ret;

  if (argc ==2)
    nObjects = atoi(argv[1]);

  srand(time(NULL));

  for (i = 0; i < nObjects; i++) {
    /* initialize the ApMon structure */
    ApMon *apm = apMon_init(initurl);
    if (apm == NULL)
      apMon_errExit("\nError initializing the ApMon structure");

    val = 10 * (double)rand() / RAND_MAX;
    ret = apMon_sendDoubleParameter(apm, "TestCluster1_c", NULL, "my_cpu_load", 
				   val);
    sleep(2);
    // free the memory and terminate the background thread
    apMon_free(apm);
  }

  return 0;
}
