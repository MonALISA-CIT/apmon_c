/**
 * \file example_sensor.c
 * This example shows how ApMon can be used for collecting system monitoring
 * information. The program acts like a simple sensor, which only sends 
 * system monitoring datagrams in the background thread. The time interval at
 * which the datagrams are sent can be set from the destinations_s.conf file.
 */ 
#include <stdlib.h> 
#include <time.h>

#include "ApMon.h"

int main(int argc, char **argv) {
  char *filename = "destinations_s.conf";  
  ApMon *apm;

  setLogLevel("FINE");
  apm = apMon_init(filename);
  if (apm == NULL)
    apMon_errExit("\nError initializing the ApMon structure");
  
  apMon_setRecheckInterval(apm, 120);
  while (TRUE) {
    sleep(1);
    
  }
  
  return 0;
}
