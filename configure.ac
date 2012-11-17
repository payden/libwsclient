#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([libwsclient], [1.0.1], [payden@paydensutherland.com])
AM_INIT_AUTOMAKE
LT_INIT([disable-static])
AC_CONFIG_SRCDIR([wsclient.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
# Checks for programs.
AC_PROG_CC
AC_PROG_CXX



# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netdb.h stdlib.h string.h sys/socket.h unistd.h netinet/in.h stddef.h sys/time.h])

AC_C_INLINE
# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strstr strchr gettimeofday])
AC_CHECK_LIB(pthread, pthread_create, [], [
				       echo "This library requires pthread"
				       exit -1
				       ])
AC_CHECK_LIB(ssl, SSL_CTX_new, [], [
						echo "OpenSSL not found, building without SSL support"
						])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
