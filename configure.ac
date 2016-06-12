#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sniff-cookies], [1.1.0], [https://github.com/SkypLabs/sniff-cookies/issues])
AC_CONFIG_SRCDIR([src/sniff_cookies.c])
#AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live], [], [
			  echo "pcap library is required for this program"
			  exit -1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa strstr])

AC_CONFIG_FILES([Makefile
				 lib/Makefile
				 src/Makefile])

AC_PROG_RANLIB
AC_OUTPUT
