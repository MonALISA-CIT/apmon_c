/**
 * \file mon_constants.c
 * Here we define the names of the parameters provided by the automatic
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

#include "mon_constants.h"

int initSysParams(char *sysMonitorParams[]) {
  /* percent of the time spent by the CPU in user mode */
  sysMonitorParams[SYS_CPU_USR] = "cpu_usr";
  /* percent of the time spent by the CPU in system mode */
  sysMonitorParams[SYS_CPU_SYS] = "cpu_sys"; 
  /* percent of the CPU idle time */
  sysMonitorParams[SYS_CPU_IDLE] = "cpu_idle";
 /* percent of the time spent by the CPU in nice mode */
  sysMonitorParams[SYS_CPU_NICE] = "cpu_nice";
  /* CPU usage percent */
  sysMonitorParams[SYS_CPU_USAGE] = "cpu_usage";
  /* number of pages paged in (in the last interval) */
  sysMonitorParams[SYS_PAGES_IN] = "pages_in";
  /* number of pages paged out (in the last interval) */
  sysMonitorParams[SYS_PAGES_OUT] = "pages_out";
  /* number of swap pages brought in (in the last interval) */;
  sysMonitorParams[SYS_SWAP_IN] = "swap_in";
  /* number of swap pages brought out (in the last interval) */;
  sysMonitorParams[SYS_SWAP_OUT] = "swap_out";
  /* average system load over the last minute */
  sysMonitorParams[SYS_LOAD1] = "load1";
  /* average system load over the last 5 min */
  sysMonitorParams[SYS_LOAD5] = "load5";
  /* average system load over the last 15 min */;
  sysMonitorParams[SYS_LOAD15] = "load15";
  /* amount of currently used memory, in MB */
  sysMonitorParams[SYS_MEM_USED] = "mem_used";
 /* amount of free memory, in MB */
  sysMonitorParams[SYS_MEM_FREE] = "mem_free";
  /* used system memory in percent */
  sysMonitorParams[SYS_MEM_USAGE] = "mem_usage";
  /* amount of currently used swap, in MB */
  sysMonitorParams[SYS_SWAP_USED] = "swap_used";
  /* amount of free swap, in MB */
  sysMonitorParams[SYS_SWAP_FREE] = "swap_free";
  /* swap usage in percent */
  sysMonitorParams[SYS_SWAP_USAGE] = "swap_usage";
  /* network (input) transfer in KBps */
  sysMonitorParams[SYS_NET_IN] = "net_in";
 /* network (output) transfer in KBps */
  sysMonitorParams[SYS_NET_OUT] = "net_out";
  /* number of network errors */
  sysMonitorParams[SYS_NET_ERRS] = "net_errs";
  /* number of processes in the  system */
  sysMonitorParams[SYS_PROCESSES] = "processes";
  /* system uptime in days */
  sysMonitorParams[SYS_UPTIME] = "uptime";
  /* number of sockets */
  sysMonitorParams[SYS_NET_SOCKETS] = "net_sockets";
  /* number of TCP sockets in different states */
  sysMonitorParams[SYS_NET_TCP_DETAILS] = "net_tcp_details";
 
  return 25;
}

int initGenParams(char *genMonitorParams[]) {
  genMonitorParams[GEN_HOSTNAME] = "hostname";
  genMonitorParams[GEN_IP] = "ip";
  genMonitorParams[GEN_CPU_MHZ] = "cpu_MHz";
  genMonitorParams[GEN_NO_CPUS] = "no_CPUs";
  /* total amount of system memory in MB */
  genMonitorParams[GEN_TOTAL_MEM] = "total_mem";
  /* total amount of swap in MB */
  genMonitorParams[GEN_TOTAL_SWAP] = "total_swap";
  genMonitorParams[GEN_TOTAL_SWAP] = "total_swap";
  genMonitorParams[GEN_CPU_VENDOR_ID] = "cpu_vendor_id";
  genMonitorParams[GEN_CPU_FAMILY] = "cpu_family";
  genMonitorParams[GEN_CPU_MODEL] = "cpu_model";
  genMonitorParams[GEN_CPU_MODEL_NAME] = "cpu_model_name";
  genMonitorParams[GEN_BOGOMIPS] = "bogomips";

  return 11;
}

int initJobParams(char *jobMonitorParams[]) {

  /* elapsed time from the start of this job in seconds */
  jobMonitorParams[JOB_RUN_TIME] = "run_time";
  /* processor time spent running this job in seconds */
  jobMonitorParams[JOB_CPU_TIME] = "cpu_time";
  /* current percent of the processor used for this job, as reported by ps */
  jobMonitorParams[JOB_CPU_USAGE] = "cpu_usage";
  /* percent of the memory occupied by the job, as reported by ps */
  jobMonitorParams[JOB_MEM_USAGE] = "mem_usage";
  /* size in KB of the resident image size of the job, as reported by ps */
  jobMonitorParams[JOB_RSS] = "rss";
 /* size in KB of the virtual memory occupied by the job, as reported by ps */
  jobMonitorParams[JOB_VIRTUALMEM] = "virtualmem";
  /* size in MB of the working directory of the job (including the files
   referenced by symbolic links) */
  jobMonitorParams[JOB_WORKDIR_SIZE] = "workdir_size";
  /* size in MB of the disk partition containing the
     working directory */
  jobMonitorParams[JOB_DISK_TOTAL] = "disk_total";
  /* size in MB of the used disk space on the  partition containing the working directory */
  jobMonitorParams[JOB_DISK_USED] = "disk_used";
  /* size in MB of the free disk space on the partition containing the working directory */
  jobMonitorParams[JOB_DISK_FREE] = "disk_free";
  /* percent of the used disk on the partition containing the working directory */
  jobMonitorParams[JOB_DISK_USAGE] = "disk_usage";
  /* number of opened file descriptors */
  jobMonitorParams[JOB_OPEN_FILES] = "open_files";
  return 12;
}

void initSocketStatesMapTCP(char *socketStatesMapTCP[]) {
  socketStatesMapTCP[STATE_ESTABLISHED] = "ESTABLISHED";
  socketStatesMapTCP[STATE_SYN_SENT] = "SYN_SENT";
  socketStatesMapTCP[STATE_SYN_RECV] = "SYN_RECV";
  socketStatesMapTCP[STATE_FIN_WAIT1] = "FIN_WAIT1";
  socketStatesMapTCP[STATE_FIN_WAIT2] = "FIN_WAIT2";
  socketStatesMapTCP[STATE_TIME_WAIT] = "TIME_WAIT";
  socketStatesMapTCP[STATE_CLOSED] = "CLOSED";
  socketStatesMapTCP[STATE_CLOSE_WAIT] = "CLOSE_WAIT";
  socketStatesMapTCP[STATE_LAST_ACK] = "LAST_ACK";
  socketStatesMapTCP[STATE_LISTEN] = "LISTEN";
  socketStatesMapTCP[STATE_CLOSING] = "CLOSING"; 
  socketStatesMapTCP[STATE_UNKNOWN] = "UNKNOWN";

}
