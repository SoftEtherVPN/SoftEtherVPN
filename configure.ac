#  Copyright 2014 Darik Horn <dajhorn@vanadac.com>
#
#  This file is part of SoftEther.
#
#  SoftEther is free software: you can redistribute it and/or modify it under
#  the terms of the GNU General Public License as published by the Free 
#  Software Foundation, either version 2 of the License, or (at your option)
#  any later version.
#
#  SoftEther is distributed in the hope that it will be useful, but WITHOUT ANY
#  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
#  details.
#
#  You should have received a copy of the GNU General Public License along with
#  SoftEther.  If not, see <http://www.gnu.org/licenses/>.


AC_INIT([SoftEther], [1], [http://www.vpnusers.com/], [softether], [http://www.softether.org/])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([autotools])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_AR
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_HEADERS([softether_config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/Mayaqua/Makefile
	src/Cedar/Makefile
	src/hamcorebuilder/Makefile
	src/libsoftether/Makefile
	src/bin/hamcore/Makefile
	src/vpnserver/Makefile
	src/vpnclient/Makefile
	src/vpnbridge/Makefile
	src/vpncmd/Makefile
	src/softetherd/Makefile
])


AC_ARG_ENABLE(
	[debug],
	AS_HELP_STRING([--enable-debug], [build SoftEther with debugging features]),
	[debug=yes]
)
AM_CONDITIONAL([CONFIGURE_ENABLE_DEBUG], [test _"$debug" = _yes])


AX_PTHREAD([
	AC_SUBST(PTHREAD_CC)
	AC_SUBST(PTHREAD_CFLAGS)
	AC_SUBST(PTHREAD_LIBS)
],[
	AC_MSG_ERROR([pthread capabilities not found])
])

CC="$PTHREAD_CC"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
LIBS="$PTHREAD_LIBS $LIBS"


AX_CHECK_OPENSSL([
	AC_SUBST(OPENSSL_LIBS)
	AC_SUBST(OPENSSL_LDFLAGS)
],[
	AC_MSG_ERROR([openssl not found])
])

LIBS="$LIBS $OPENSSL_LIBS"
LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"


# This macro automatically updates build variables.
AX_CHECK_ZLIB(, AC_MSG_ERROR([zlib not found]))


AX_WITH_CURSES
if test "_$ax_cv_curses" != _yes
then
	AC_MSG_ERROR([libcurses, libncurses, or libncursesw not found])
else
	AC_SUBST(CURSES_LIB)
	LIBS="$LIBS $CURSES_LIB"
fi


AX_LIB_READLINE
if test "_$ax_cv_lib_readline" = _no
then
	AC_MSG_ERROR([libreadline not found])
else
	: This macro automatically updates build variables.
fi


AC_OUTPUT
