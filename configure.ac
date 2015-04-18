#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([RabbitSign], [2.1], [floppusmaximus@users.sf.net])
AC_CONFIG_SRCDIR([src/rabbitsign.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_TOOL([AR], [ar], [false])
AC_PROG_RANLIB
AC_PROG_MAKE_SET

if test "x$GCC" = "xyes" ; then
  CFLAGS="$CFLAGS -W -Wall -Wwrite-strings"
fi

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([limits.h sys/time.h assert.h])

AC_ARG_VAR(GMP_CFLAGS, [Extra C compiler flags required for GMP (default empty)])
AC_ARG_VAR(GMP_LIBS, [Extra libraries required for GMP (default -lgmp)])

AC_ARG_WITH(gmp,
 AC_HELP_STRING([--with-gmp], [use the GNU MP library if found]),
 [ check_gmp=$withval ], [ check_gmp=yes ])

if test "x$check_gmp" = "xyes" ; then
  save_cflags="$CFLAGS"
  CFLAGS="$CFLAGS $GMP_CFLAGS"
  AC_CHECK_HEADER([gmp.h], [ have_gmp=yes ], [ have_gmp=no ])
  CFLAGS="$save_cflags"
else
  have_gmp=no
fi

if test "x$have_gmp" = "xyes" ; then
  AC_DEFINE(HAVE_GMP_H, 1,
	    [Define to 1 if you have gmp.h.])
  if test "x$GMP_LIBS" = "x" ; then
    GMP_LIBS="-lgmp"
  fi
  mpzobjs=""
  opt_build_rskeygen=rskeygen$EXEEXT
  opt_install_rskeygen=install-rskeygen
else
  mpzobjs=mpz.$OBJEXT

  AC_CHECK_SIZEOF(short)
  AC_CHECK_SIZEOF(int)
  AC_CHECK_SIZEOF(long)
fi

AC_DEFINE(USE_MPZ_GCDEXT, 1,
	  [Define to 1 to enable the use of mpz_gcdext().])

AC_SUBST([mpzobjs])
AC_SUBST([opt_build_rskeygen])
AC_SUBST([opt_install_rskeygen])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_PROTOTYPES
AC_C_BIGENDIAN
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp stricmp strrchr rindex strchr index memcpy random rand])

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 src/Makefile
                 test/Makefile])
AC_OUTPUT
