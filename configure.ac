#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_include([version.m4])
AC_PREREQ([2.59])
AC_INIT([jicmp6], [VERSION_NUMBER], [https://www.opennms.com])

RELEASE=1
AC_SUBST([RELEASE])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.9 foreign])
AC_ENABLE_STATIC([no])
LT_PREREQ([2.0])

# don't test c++ and f77 in libtool
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
LT_INIT
AC_PROG_INSTALL
AC_C_BIGENDIAN
AX_LIB_SOCKET_NSL
CL_AS_NOEXECSTACK
ONMS_CHECK_JDK([1.8])
ONMS_CHECK_SUNCC
ONMS_SET_CC_ARCH_CFLAGS
ONMS_SET_CC_WARNING_CFLAGS

AM_RPM_INIT
AM_CONDITIONAL(MAKE_RPMS, test x$make_rpms = xtrue)

PRINT_VAR(JAVA_HOME)
PRINT_VAR(JAVA)
PRINT_VAR(JAVAC)
PRINT_VAR(JAVAH)
PRINT_VAR(JAR)
PRINT_VAR(JNI_INCLUDES)

AC_INCLUDES_DEFAULT
AC_PROG_EGREP

# check for jni.h
CPPFLAGS="$CPPFLAGS $JNI_INCLUDES -I."
AC_CHECK_HEADER([jni.h], [], [AC_MSG_ERROR([cannot find jni.h header with CPPFLAGS="$CPPFLAGS"])])

AC_CHECK_HEADERS([sys/types.h netinet/in.h],[],[],[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
])

AC_CHECK_HEADERS([netinet/icmp6.h],[],[],[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

AC_CHECK_HEADERS([AvailabilityMacros.h libkern/OSByteOrder.h architecture/byte_order.h byteswap.h errno.h malloc.h netdb.h stdlib.h sys/byteorder.h sys/time.h], [], [], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
])

# check for socklen_t
ONMS_CHECK_SOCKLEN_T

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# should be part of stdlib
AC_CHECK_FUNC([getenv], AC_DEFINE([HAVE_GETENV], [1], [If present, the getenv function allows us to read environment variables.]))
AC_CHECK_FUNC([setsockopt], AC_DEFINE([HAVE_SETSOCKOPT], [1], [If present, the OS supports setsockopt.]))

AC_CHECK_TYPE([struct timeval],
	[],
	[ AC_MSG_ERROR([cannot find struct timeval]) ],
	[
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
])

gl_BYTESWAP

ARCH_PKG="$host_cpu"
AC_SUBST([ARCH_PKG])

UNAME_R="`uname -r`"
AC_SUBST([UNAME_R])
UNAME_S="`uname -s`"
AC_SUBST([UNAME_S])

on_win32=no
case $host_os in
	mingw32*)
		on_win32=yes
		;;
esac

AM_CONDITIONAL([WIN32], [test x$on_win32 = xyes])

SHORT_VERSION="$(echo "$VERSION" | cut -d. -f1-2)"
AC_SUBST([SHORT_VERSION])

AC_CONFIG_FILES([Makefile jicmp6.spec JICMP6.te pom.xml])
AC_CONFIG_FILES([tests.sh], [chmod +x tests.sh])
AC_OUTPUT
