/**
 * \file mon_constants.h
 * Definitions of the constants associated with the parameters from
 * job and system monitoring.
 */

/*
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

#ifndef mon_constants_h
#define mon_constants_h


//SYS_* Specific
#define SYS_LOAD1            0
#define SYS_LOAD5            1
#define SYS_LOAD15           2
#define SYS_CPU_USR          3
#define SYS_CPU_SYS          4
#define SYS_CPU_IDLE         5
#define SYS_CPU_NICE         6
#define SYS_CPU_USAGE        7
#define SYS_MEM_FREE         8
#define SYS_MEM_USED         9
#define SYS_MEM_USAGE        10
#define SYS_PAGES_IN         11
#define SYS_PAGES_OUT        12
#define SYS_NET_IN           13
#define SYS_NET_OUT          14
#define SYS_NET_ERRS         15
#define SYS_SWAP_FREE        16
#define SYS_SWAP_USED        17
#define SYS_SWAP_USAGE       18
#define SYS_SWAP_IN          19
#define SYS_SWAP_OUT         20
#define SYS_PROCESSES        21
#define SYS_UPTIME           22
#define SYS_NET_SOCKETS      23
#define SYS_NET_TCP_DETAILS  24

//GENERIC_*
#define GEN_HOSTNAME         0
#define GEN_IP               1
#define GEN_CPU_MHZ          2
#define GEN_NO_CPUS          3
#define GEN_TOTAL_MEM        4
#define GEN_TOTAL_SWAP       5
#define GEN_CPU_VENDOR_ID    6
#define GEN_CPU_FAMILY       7
#define GEN_CPU_MODEL        8
#define GEN_CPU_MODEL_NAME   9
#define GEN_BOGOMIPS         10

//JOB_*
#define JOB_RUN_TIME         0
#define JOB_CPU_TIME         1
#define JOB_CPU_USAGE        2
#define JOB_MEM_USAGE        3
#define JOB_WORKDIR_SIZE     4
#define JOB_DISK_TOTAL       5
#define JOB_DISK_USED        6
#define JOB_DISK_FREE        7
#define JOB_DISK_USAGE       8
#define JOB_VIRTUALMEM       9
#define JOB_RSS              10 
#define JOB_OPEN_FILES       11

// Indexes for TCP, UDP, ICM, Unix in the table which stores the number of 
// open sckets
#define SOCK_TCP             0
#define SOCK_UDP             1
#define SOCK_ICM             2
#define SOCK_UNIX            3

// Constants for the possible states of the TCP sockets
#define STATE_ESTABLISHED    0
#define STATE_SYN_SENT       1
#define STATE_SYN_RECV       2
#define STATE_FIN_WAIT1      3
#define STATE_FIN_WAIT2      4
#define STATE_TIME_WAIT      5
#define STATE_CLOSED         6
#define STATE_CLOSE_WAIT     7
#define STATE_LAST_ACK       8
#define STATE_LISTEN         9
#define STATE_CLOSING       10 
#define STATE_UNKNOWN       11

#define N_TCP_STATES        12

/**
 * Fills the array given as argument with the names of the system parameters.
 */
int initSysParams(char *sysMonitorParams[]);

/**
 * Fills the array given as argument with the names of the general system 
 * parameters.
 */
int initGenParams(char *genMonitorParams[]);

/**
 * Fills the array given as argument with the names of the job parameters.
 */
int initJobParams(char *jobMonitorParams[]);

/**
 * Fills the table that associates the TCP socket state names with the
 * symbolic constants.
 */
void initSocketStatesMapTCP(char *socketStatesMapTCP[]);

#endif
