dnl Process this file with autoconf to produce a configure script.

dnl Minimum Autoconf version required.
AC_PREREQ([2.69])

AC_INIT([GNU Time],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [bug-time@gnu.org], [],
        [https://www.gnu.org/software/time/])

AC_CONFIG_SRCDIR([src/time.c])

dnl Must come before AM_INIT_AUTOMAKE.
AC_CONFIG_AUX_DIR([build-aux])

dnl Where to generate output; srcdir location.
AC_CONFIG_HEADERS([config.h:config.in])

AM_INIT_AUTOMAKE([
	1.11.1
	subdir-objects
	color-tests
	parallel-tests
])



dnl Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_C_INLINE

# Since we use gnulib: gl_EARLY must be called as soon as possible after
# the C compiler is checked.  The others could be later, but we just
# keep everything together.
gl_EARLY
gl_INIT

# Add extra compilation warnings. These will only apply to src/*.c not to
# any gnulib modules). See $(WARN_CFLAGS) in Makefile.am
gl_WARN_ADD([-Wall])
gl_WARN_ADD([-Wextra])
gl_WARN_ADD([-Wformat-security])
gl_WARN_ADD([-Wswitch-enum])
gl_WARN_ADD([-Wswitch-default])
gl_WARN_ADD([-Wformat-nonliteral])
gl_WARN_ADD([-Wunused-parameter])
gl_WARN_ADD([-Wfloat-equal])
gl_WARN_ADD([-fdiagnostics-show-option])
gl_WARN_ADD([-funit-at-a-time])
gl_WARN_ADD([-Wmissing-format-attribute])
gl_WARN_ADD([-Wstrict-overflow])
gl_WARN_ADD([-Wsuggest-attribute=const])
gl_WARN_ADD([-Wsuggest-attribute=pure])
AC_SUBST([WARN_CFLAGS])

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS(strerror)


# What memory units are reported by getrusage(2) ?
warn_getrusage_mem_units=
if test -z "$time_getrusage_mem_units" ; then
  # if envvar 'time_getrusage_mem_units' isn't set,
  # autodetect based on OS.
  case "$host_os" in
    minix*|aix*|*bsd*|linux*|gnu*)
                     time_getrusage_mem_units=kb ;;

    macos*|darwin*)  time_getrusage_mem_units=bytes ;;

    solaris*)        time_getrusage_mem_units=pages ;;

    # As a fallback, assume KB (the most common value).
    # Set the 'warn' variable to warn the user at the end
    # of ./configure
    *) time_getrusage_mem_units=kb
       warn_getrusage_mem_units=yes
       ;;
  esac
fi

# Define the configuration item
case $time_getrusage_mem_units in
  kb)
     AC_DEFINE([GETRUSAGE_RETURNS_KB],[1],
                [Define to 1 if getrusage(2) on this systems returns
                 ru_maxrss in kilobytes])
     ;;

  bytes)
     AC_DEFINE([GETRUSAGE_RETURNS_BYTES],[1],
               [Define to 1 if getrusage(2) on this systems returns
                ru_maxrss in bytes])
     ;;

  pages)
     AC_DEFINE([GETRUSAGE_RETURNS_PAGES],[1],
               [Define to 1 if getrusage(2) on this systems returns
                ru_maxrss in pages])
     ;;

  *) # should never happen
     AC_MSG_ERROR([invalid 'time_getrusage_mem_units' value
                   '$time_getrusage_mem_units'])
     ;;
esac


# This is needed when building outside the source dir
# with --disable-dependency-tracking.
# Inspired by sed's https://bugs.gnu.org/25371
AS_MKDIR_P([lib])
AS_MKDIR_P([src])
AS_MKDIR_P([doc])
AS_MKDIR_P([tests])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Warn the user if getrusage(2) behaviour on this OS is unknown
if test "$warn_getrusage_mem_units" ; then
  AC_MSG_WARN([unknown getrusage behavior on operating system '$host_os'.
               Assuming Kilobytes.
               please report this with the output of 'uname -a' to
               bug-time@gnu.org])
fi
