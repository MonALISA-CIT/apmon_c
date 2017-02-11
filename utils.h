/**
 * \file utils.h
 * This file contains the declarations of some helper methods for ApMon.
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

#ifndef apmon_utils_h
#define apmon_utils_h

#define FATAL 0 /**< Logging level with minimum number of messages. */
#define WARNING 1 /**< Intermediate logging level. */
#define INFO 2 /**< Intermediate logging level. */
#define FINE 3 /**< Logging level with detailed information. */
#define DEBUG 4 /**< Logging level for debugging. */

/**
 * Returns a nonzero value if the page with the specified URL was modified 
 * since the last check.
 * @param url The address of the page.
 * @param lastModified The "Last-Modified" header that was received last time
 * the page was requested.
 */
int urlModified(char *url, char *lastModified);

/**
 * Performs a HTTP request and puts the result into a temporary file.
 * @param url The address of the web page.
 * @param reqType The type of the request (GET, POST, HEAD).
 * @param temp_filename The name of the temporary file.
 */
int httpRequest(char *url, char *reqType, char *temp_filename); 

/**
 * Determines the size of the XDR representation for a data item.
 * @param type The type of the data item (see the constants XDR_STRING, 
 * XDR_INT32, ... defined above).
 * @param value The value of the data item (only used when dealing with 
 * strings).
 */
int xdrSize(int type, char *value);

/**
 * Determines the size of a data item.
 * @param type The type of the data item (see the constants XDR_STRING, 
 * XDR_INT32, ... defined above).
 * @param value The value of the data item (only used when dealing with 
 * strings).
 */
int sizeEval(int type, char *value);

/**
 * If "address" is a hostname, it returns the corresponding IP address;
 * if "address" is an IP address, it just returns a copy of the address.
 */
char *findIP(char *address);

/**
 * Parses an URL and determines the hostname, the port and the file name.
 * It is used for the URLs given in the configuration file.
 * @param url The URL string.
 * @param hostname The determined hostname (this is an output parameter).
 * @param port The determined port (also an output parameter).
 * @param identifier The determined file name (also an output parameter).
 */
int parse_URL(char *url, char *hostname, int *port, char *identifier);

/**
 * Frees the memory for a 2-dimensional character array.
 * @param mat The array to be freed.
 * @param nRows The number of rows in the arrray.
 */
void freeMat(char **mat, int nRows);

/**
 * Removes the white spaces from a string.
 * @param s The string to be modified
 * @return the trimmed string.
 */
char *trimString(char *s); 

/**
 * Verifies whether an IP address is private.
 */
int isPrivateAddress(char *addr); 

/**
 * Prints the name and values of the parameters given as arguments.
 */
void logParameters(int level, int nParams, char **paramNames, 
		     int *valueTypes, char **paramValues);
/**
 * Finds the index of a string in a string array.
 * @param item The string that is searched in the array.
 * @param vect The string array.
 * @param vectDim The number of strings in the array.
 * @return The index of the string or -1 if the string is not found.
 */
int getVectIndex(char *item, char **vect, int vectDim);



/** Logs the message given as argument if the current logging level is 
 * greater than or equal to msgLevel. 
 */
void logger(int msgLevel, const char *msg);

/** Sets the ApMon logging level to newLevel. Possible values for newLevel
 * are FATAL, WARNING, INFO, FILE, DEBUG.
 */
void setLogLevel(char *newLevel_s);

#endif
