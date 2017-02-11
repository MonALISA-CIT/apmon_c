/**
 * \file monitor_utils.h
 * This file contains declarations for functions and data structured 
 * used for obtaining monitoring information.
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

#ifndef monitor_utils_h
#define monitor_utils_h

/**
 * Structure that holds information about a job, as obtained from the
 * ps command.
 */
typedef struct PsInfo {
  double etime; /* elapsed time since the job started, in seconds */
  double cputime; /* CPU time allocated so far to this job. */
  double pcpu; /* percent of the processor currently used by the job */
  double pmem; /* percent of the system memory currently used by the job */
  double rsz; /* resident image size of the job, in KB */
  double vsz; /* amount of the virtual memory occupied by the job, in KB */
  double open_fd; /* number of opened file descriptors */
} PsInfo;

/**
 * Structure that holds information about the disk usage for a job.
 */
typedef struct JobDirInfo {
  /* the size of the job's working directory */
  double workdir_size; 
  /* the size of the partition on which the working directory resides, in MB */
  double disk_total; 
  /* the amount of disk used on the working directory's partition */
  double disk_used;
  /* the amount of disk free on the working directory's partition */
  double disk_free;
  /* disk usage in percent on the working directort's partition */
  double disk_usage; 
} JobDirInfo;

/** Sends datagrams with job monitoring information for the jobs that ApMon
 * monitors. */
void apMon_sendJobInfo(ApMon *apm);

/** Sends to the destination hosts datagrams with monitorng information for 
 * a specified job. */
void apMon_sendOneJobInfo(ApMon *apm, MonitoredJob job);

/** Update the monitoring information regarding the specified job. */
int apMon_updateJobInfo(ApMon *apm, MonitoredJob job); 

/** Sends datagrams with system monitoring information to the destination
 * hosts. */
void apMon_sendSysInfo(ApMon *apm);

/** Update the system monitoring information with new values obtained 
    from the proc/ filesystem. */
void apMon_updateSysInfo(ApMon *apm);

/** Sends datagrams with general system monitoring information to the 
 * destination hosts. */
void apMon_sendGeneralInfo(ApMon *apm); 

/** Update the general monitoring information. */
void apMon_updateGeneralInfo();

/** Initializes a temporary structure with information on the parameters that 
 * are monitored. */
void apMon_initMonitoring(MonitorConf *mconf);

/** Copies the monitoring settings from the temporary structure to the
 * ApMon object. */
void apMon_copyMonSettings(ApMon *apm, MonitorConf mconf);

/** Copies the parameter names from the temporary structure to the ApMon
 * object. */
void apMon_copyParamNames(ApMon *apm, MonitorConf mconf);

/** Parses an xApMon line from the configuration file. */
void apMon_parseXApMonLine(MonitorConf *mconf, char *line);

/** Determines all the descendants of a given process. */
long *apMon_getChildren(long pid, int *nChildren);

/** Obtains monitoring information for a given job and all its sub-jobs 
 * (descendant processes) with the aid of the ps command. 
 */
int apMon_readJobInfo(long pid, PsInfo *info);

/**
 * Function that parses a time formatted like "days-hours:min:sec" and returns 
 * the corresponding number of seconds.
 */
long apMon_parsePSTime(char *s);

/**
 * If there is an work directory defined, then compute the used space in that 
 * directory and the free disk space on the partition to which that directory 
 * belongs. Sizes are given in MB.
 */
int apMon_readJobDiskUsage(MonitoredJob job, JobDirInfo *info); 

#endif
