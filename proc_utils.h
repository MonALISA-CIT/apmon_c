/**
 * \file proc_utils.h
 * This file contains declarations for various functions that extract 
 * information from the proc/ filesystem.
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

#ifndef apmon_procutils_h
#define apmon_procutils_h

#include <time.h>
#include "ApMon.h"

#define PROCUTILS_ERROR -2
#define RUNTIME_ERROR -3

/**
 * Calculates the average CPU usage (in percent) in the time interval between
 * lastSysInfoSend and the current moment of time. The ApMon structure is 
 * updated with the new values.
 */
int procutils_updateCPUUsage(ApMon *apm);

/** Calculates the parameters pages_in, pages_out, swap_in, swap_out,
    cpu_usage and updates the ApMon structure with the new values.
*/
int procutils_updateSwapPages(ApMon *apm);

/**
 * Obtains the CPU load in the last 1, 5 and 15 mins and the number of 
 * processes currently running and updates the ApMon structure with the
 * new values.
 */
int procutils_updateLoad(ApMon *apm);

/**
 * Obtains the total amount of memory and the total amount of swap (in MB)
 * and stores them in the variables given as parameters.
 */
int procutils_getSysMem(double *totalMem, double *totalSwap) ;

/**
 * Obtains the amount of memory and of swap currently in use and updates
 * the ApMon structure with the new values.
 */
int procutils_updateMemUsed(ApMon *apm);

/**
 * Obtains the names of the network interfaces (excepting the loopback one).
 * @param nInterfaces Output parameter which will store the number of 
 * network interfaces.
 * @param names Output parameter which will store the names of the
 * interfaces.
 */
int procutils_getNetworkInterfaces(int *nInterfaces, char names[][20]);

/**
 * Obtains monitoring information for all the network interfaces, for the 
 * time interval between the moment when the last system monitoring datagram
 * was sent and the present moment.
 * @param apm The ApMon object in which we store the information.
 */  
int procutils_getNetInfo(ApMon *apm);

/**
 * Returns the number of CPUs in the system.
 */
int procutils_getNumCPUs();

/**
 * Obtains CPU information (vendor, model, frequency, bogomips) and fills the
 * corresponding fields in the ApMon object.
 */
int procutils_getCPUInfo(ApMon *apm);

/**
 * Returns the system boot time, in seconds since the Epoch.
 */
long procutils_getBootTime();

/**
 * Returns the system uptime, in days.
 */
double procutils_getUpTime();

/**
 * Obtains statistics about the total number of processes and
 * the number of processes in each state.
 * Possible states: 
 *   D uninterruptible sleep (usually IO)
 *   R runnable (on run queue)
 *   S sleeping
 *   T traced or stopped
 *   W paging (2.4 kernels and older only)
 *   X dead
 *   Z a defunct ("zombie") process
 */
int procutils_getProcesses(double *processes, double states[]);


/**
 * Obtains the number of opened file descriptors for the process with
 * the given pid.
 */
int procutils_countOpenFiles(long pid);

/**
 * Obtains information about the currently opened sockets.
 */
int procutils_getNetstatInfo(ApMon *apm); 

#endif
