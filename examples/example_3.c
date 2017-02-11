/**
 * \file example_3.c
 * This example illustrates the way to send several parameters in the
 * same UDP datagram, with the functions sendParameters() and 
 * sendTimedParameters().
 * The number of parameter sets can be specified in the command line (if 
 * it is not, the default is 20). A parameter set contains: the OS name and two 
 * random values for the parameters "my_cpu_load" and "my_cpu_idle".
 * The number of parameters that will be sent can be specified in the command 
 * line (if it is not, the default is 20).For each parameter set two 
 * datagrams are sent: one with a timestamp and one without a timestamp. For 
 * the latter, the local time at the MonALISA host will be considered.
 * The file "destinations_3.conf" contains the addresses of the hosts to which
 * we send the parameters, and also the corresponding ports.
 */ 
#include <stdlib.h> 
#include <time.h>

#include "ApMon.h"

int main(int argc, char **argv) {
  char *filename = "destinations_3.conf";  
  char *osname = "linux";
  int nDatagrams;
  int ret, i, timestamp;
  float val;
  int val2;

  int nParameters = 3;
  char **paramNames, **paramValues;
  int *valueTypes;

  ApMon *apm;

  if (argc == 2) 
    nDatagrams = atoi(argv[1]);
  else
    nDatagrams = 20;

  /* initialize the ApMon data structure */
  apm = apMon_init(filename);
  if (apm == NULL)
    apMon_errExit("\nError initializing ApMon structure.");

  apMon_setMaxMsgRate(apm, 100);    
  srand(time(NULL));

  /* allocate memory for the arrays */
  paramNames = (char **)malloc(nParameters * sizeof(char *));
  paramValues = (char **)malloc(nParameters * sizeof(char *));
  valueTypes = (int *)malloc(nParameters * sizeof(int));

  /* initialize the parameter names and types */
  paramNames[0] = "my_cpu_load";
  valueTypes[0] = XDR_REAL32;
  paramNames[1] = "my_os_name";
  valueTypes[1] = XDR_STRING;
  paramNames[2] = "my_cpu_idle";
  valueTypes[2] = XDR_INT32;

  /* initialize the pointers to the values */
  /* (the values will change, but the addresses remain the same) */ 
  paramValues[0] = (char *)&val;
  paramValues[1] = osname; 
  paramValues[2] = (char *)&val2;

  /* start creating the datagrams */
  for (i = 1; i <= nDatagrams; i++) {

    /* add a value for the CPU load (random between 0 and 2) */
    val = 2 * (float)rand() / RAND_MAX;
    printf("Sending %f for my_cpu_load\n", val);

    /* add a value for the CPU idle percentage (random between 0 and 50) */
    val2 = (int)(50 * (double)rand() / RAND_MAX);
    printf("Sending %d for my_cpu_idle\n", val2);
    /* add a value for the CPU load */
    /* ret3 = addMParam(apm, "cpu_idle", XDR_INT32, (char *)&val2); */

    /* send the datagram without the timestamp */
    ret = apMon_sendParameters(apm, "MyCluster_3_c", "MyNode2", nParameters, 
			 paramNames, valueTypes, paramValues);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending the parameters \n");
    }

    /* now send the datagram with the timestamp */
    timestamp = time(NULL) - (3 * 3600);  /* as if it was sent 3h ago */
    ret = apMon_sendTimedParameters(apm, "MyCluster_3_c_3", "MyNode2", 
		  nParameters, paramNames, valueTypes, paramValues, timestamp);
    if (ret == RET_ERROR) {
      apMon_free(apm);
      apMon_errExit("\nError sending the parameters \n");
    }
  }

  apMon_free(apm);
  return 0;
}
