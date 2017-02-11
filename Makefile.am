if WITHDOXYGEN
doc: Doxyfile all
	doxygen
endif


AM_CFLAGS = -g
INCLUDES = -I./ 
lib_LTLIBRARIES = libapmonc.la
include_HEADERS = ApMon.h utils.h monitor_utils.h proc_utils.h mon_constants.h

libapmonc_la_SOURCES = ApMon.c utils.c monitor_utils.c proc_utils.c mon_constants.c

libapmonc_la_LIBADD = -lpthread 
libapmonc_la_LDFLAGS = -version-info 2:6:0

SUBDIRS	= . examples 