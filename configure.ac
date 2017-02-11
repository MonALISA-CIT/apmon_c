#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT([ApMon_c], [2.2.2])

AC_CONFIG_SRCDIR([ApMon.h])
AM_INIT_AUTOMAKE([ApMon_c], 2.2.2)
AM_CONFIG_HEADER(config.h)


# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_PROG([HAVEDOXYGEN],[doxygen],[yes],[no])
AM_CONDITIONAL(WITHDOXYGEN, test x"$HAVEDOXYGEN" = xyes)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_HEADER_TIME
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero gethostbyname gethostname inet_ntoa memset socket strchr strdup strrchr strstr])

AC_CONFIG_FILES([Makefile
		examples/Makefile])
AC_OUTPUT
