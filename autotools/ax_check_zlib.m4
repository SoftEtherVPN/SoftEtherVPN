# ===========================================================================
#       http://www.gnu.org/software/autoconf-archive/ax_check_zlib.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_ZLIB([action-if-found], [action-if-not-found])
#
# DESCRIPTION
#
#   This macro searches for an installed zlib library. If nothing was
#   specified when calling configure, it searches first in /usr/local and
#   then in /usr, /opt/local and /sw. If the --with-zlib=DIR is specified,
#   it will try to find it in DIR/include/zlib.h and DIR/lib/libz.a. If
#   --without-zlib is specified, the library is not searched at all.
#
#   If either the header file (zlib.h) or the library (libz) is not found,
#   shell commands 'action-if-not-found' is run. If 'action-if-not-found' is
#   not specified, the configuration exits on error, asking for a valid zlib
#   installation directory or --without-zlib.
#
#   If both header file and library are found, shell commands
#   'action-if-found' is run. If 'action-if-found' is not specified, the
#   default action appends '-I${ZLIB_HOME}/include' to CPFLAGS, appends
#   '-L$ZLIB_HOME}/lib' to LDFLAGS, prepends '-lz' to LIBS, and calls
#   AC_DEFINE(HAVE_LIBZ). You should use autoheader to include a definition
#   for this symbol in a config.h file. Sample usage in a C/C++ source is as
#   follows:
#
#     #ifdef HAVE_LIBZ
#     #include <zlib.h>
#     #endif /* HAVE_LIBZ */
#
# LICENSE
#
#   Copyright (c) 2008 Loic Dachary <loic@senga.org>
#   Copyright (c) 2010 Bastien Chevreux <bach@chevreux.org>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 14

AU_ALIAS([CHECK_ZLIB], [AX_CHECK_ZLIB])
AC_DEFUN([AX_CHECK_ZLIB],
#
# Handle user hints
#
[AC_MSG_CHECKING(if zlib is wanted)
zlib_places="/usr/local /usr /opt/local /sw"
AC_ARG_WITH([zlib],
[  --with-zlib=DIR         root directory path of zlib installation @<:@defaults to
                          /usr/local or /usr if not found in /usr/local@:>@
  --without-zlib          to disable zlib usage completely],
[if test "$withval" != no ; then
  AC_MSG_RESULT(yes)
  if test -d "$withval"
  then
    zlib_places="$withval $zlib_places"
  else
    AC_MSG_WARN([Sorry, $withval does not exist, checking usual places])
  fi
else
  zlib_places=
  AC_MSG_RESULT(no)
fi],
[AC_MSG_RESULT(yes)])

#
# Locate zlib, if wanted
#
if test -n "${zlib_places}"
then
	# check the user supplied or any other more or less 'standard' place:
	#   Most UNIX systems      : /usr/local and /usr
	#   MacPorts / Fink on OSX : /opt/local respectively /sw
	for ZLIB_HOME in ${zlib_places} ; do
	  if test -f "${ZLIB_HOME}/include/zlib.h"; then break; fi
	  ZLIB_HOME=""
	done

  ZLIB_OLD_LDFLAGS=$LDFLAGS
  ZLIB_OLD_CPPFLAGS=$CPPFLAGS
  if test -n "${ZLIB_HOME}"; then
        LDFLAGS="$LDFLAGS -L${ZLIB_HOME}/lib"
        CPPFLAGS="$CPPFLAGS -I${ZLIB_HOME}/include"
  fi
  AC_LANG_SAVE
  AC_LANG_C
  AC_CHECK_LIB([z], [inflateEnd], [zlib_cv_libz=yes], [zlib_cv_libz=no])
  AC_CHECK_HEADER([zlib.h], [zlib_cv_zlib_h=yes], [zlib_cv_zlib_h=no])
  AC_LANG_RESTORE
  if test "$zlib_cv_libz" = "yes" && test "$zlib_cv_zlib_h" = "yes"
  then
    #
    # If both library and header were found, action-if-found
    #
    m4_ifblank([$1],[
                CPPFLAGS="$CPPFLAGS -I${ZLIB_HOME}/include"
                LDFLAGS="$LDFLAGS -L${ZLIB_HOME}/lib"
                LIBS="-lz $LIBS"
                AC_DEFINE([HAVE_LIBZ], [1],
                          [Define to 1 if you have `z' library (-lz)])
               ],[
                # Restore variables
                LDFLAGS="$ZLIB_OLD_LDFLAGS"
                CPPFLAGS="$ZLIB_OLD_CPPFLAGS"
                $1
               ])
  else
    #
    # If either header or library was not found, action-if-not-found
    #
    m4_default([$2],[
                AC_MSG_ERROR([either specify a valid zlib installation with --with-zlib=DIR or disable zlib usage with --without-zlib])
                ])
  fi
fi
])
