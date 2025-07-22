#!/bin/bash -norc
dnl	This file is an input file used by the GNU "autoconf" program to
dnl	generate the file "configure", which is run during Tcl installation
dnl	to configure the system for the local environment.

#-----------------------------------------------------------------------
# Sample configure.ac for Tcl Extensions.  The only places you should
# need to modify this file are marked by the string __CHANGE__
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# __CHANGE__
# Set your package name and version numbers here.
#
# This initializes the environment with PACKAGE_NAME and PACKAGE_VERSION
# set as provided.  These will also be added as -D defs in your Makefile
# so you can encode the package version directly into the source files.
#-----------------------------------------------------------------------

AC_INIT([hash],[0.4.0])

#--------------------------------------------------------------------
# Call TEA_INIT as the first TEA_ macro to set up initial vars.
# This will define a ${TEA_PLATFORM} variable == "unix" or "windows"
# as well as PKG_LIB_FILE and PKG_STUB_LIB_FILE.
#--------------------------------------------------------------------

TEA_INIT()

AC_CONFIG_AUX_DIR(tclconfig)

#--------------------------------------------------------------------
# Load the tclConfig.sh file
#--------------------------------------------------------------------

TEA_PATH_TCLCONFIG
TEA_LOAD_TCLCONFIG

#--------------------------------------------------------------------
# Load the tkConfig.sh file if necessary (Tk extension)
#--------------------------------------------------------------------

#TEA_PATH_TKCONFIG
#TEA_LOAD_TKCONFIG

#-----------------------------------------------------------------------
# Handle the --prefix=... option by defaulting to what Tcl gave.
# Must be called after TEA_LOAD_TCLCONFIG and before TEA_SETUP_COMPILER.
#-----------------------------------------------------------------------

TEA_PREFIX

#-----------------------------------------------------------------------
# Standard compiler checks.
# This sets up CC by using the CC env var, or looks for gcc otherwise.
# This also calls AC_PROG_CC and a few others to create the basic setup
# necessary to compile executables.
#-----------------------------------------------------------------------

TEA_SETUP_COMPILER

# Check for feature toggles
ENABLE_DEBUG
ENABLE_TESTMODE

#-----------------------------------------------------------------------
# Add option to disable hardware acceleration for testing
#-----------------------------------------------------------------------

AC_ARG_ENABLE([hardware-accel],
    AS_HELP_STRING([--disable-hardware-accel],[Disable AES-NI and NEON hardware acceleration, use software implementation only (useful for testing)]),
    [enable_hardware_accel=$enableval],
    [enable_hardware_accel=yes])

if test "x$enable_hardware_accel" = "xno"; then
    AC_MSG_NOTICE([Hardware acceleration disabled, using software-only implementation])
    have_aes_ni=no
    have_aes_neon=no
else
    #-----------------------------------------------------------------------
    # Check for AES-NI support (x86/x86_64)
    #-----------------------------------------------------------------------

AC_MSG_CHECKING([for AES-NI support])
save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -msse4.1 -maes"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <wmmintrin.h>
]], [[
__m128i a = _mm_setzero_si128();
__m128i b = _mm_setzero_si128();
__m128i c = _mm_aesenc_si128(a, b);
]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_AES_NI], [1], [Define if AES-NI is available])
    TEA_ADD_CFLAGS([-msse4.1 -maes])
    have_aes_ni=yes
], [
    AC_MSG_RESULT([no])
    have_aes_ni=no
])
CFLAGS="$save_CFLAGS"

#-----------------------------------------------------------------------
# Check for ARM NEON AES support (aarch64 has it by default)
#-----------------------------------------------------------------------

AC_MSG_CHECKING([for ARM NEON AES support])
save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -march=armv8-a+crypto"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <arm_neon.h>
]], [[
uint8x16_t a = vdupq_n_u8(0);
uint8x16_t b = vdupq_n_u8(0);
uint8x16_t c = vaeseq_u8(a, b);
uint8x16_t d = vaesmcq_u8(c);
]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_AES_NEON], [1], [Define if ARM NEON AES is available])
    TEA_ADD_CFLAGS([-march=armv8-a+crypto])
    have_aes_neon=yes
], [
    AC_MSG_RESULT([no])
    have_aes_neon=no
])
CFLAGS="$save_CFLAGS"

fi

#-----------------------------------------------------------------------
# __CHANGE__
# Specify the C source files to compile in TEA_ADD_SOURCES,
# public headers that need to be installed in TEA_ADD_HEADERS,
# stub library C source files to compile in TEA_ADD_STUB_SOURCES,
# and runtime Tcl library files in TEA_ADD_TCL_SOURCES.
# This defines PKG(_STUB)_SOURCES, PKG(_STUB)_OBJECTS, PKG_HEADERS
# and PKG_TCL_SOURCES.
#-----------------------------------------------------------------------

TEABASE_ADD_SOURCES([main.c md5.c sha2.c areion.c])
TEA_ADD_HEADERS([])
TEA_ADD_INCLUDES([])
TEA_ADD_LIBS([])
TEA_ADD_CFLAGS([-DSHA2_USE_INTTYPES_H -std=c17])
TEA_ADD_STUB_SOURCES([])
TEA_ADD_TCL_SOURCES([])

#--------------------------------------------------------------------
# __CHANGE__
#
# You can add more files to clean if your extension creates any extra
# files by extending CLEANFILES.
# Add pkgIndex.tcl if it is generated in the Makefile instead of ./configure
# and change Makefile.in to move it from CONFIG_CLEAN_FILES to BINARIES var.
#
# A few miscellaneous platform-specific items:
# TEA_ADD_* any platform specific compiler/build info here.
#--------------------------------------------------------------------

#CLEANFILES="$CLEANFILES pkgIndex.tcl"
if test "${TEA_PLATFORM}" = "windows" ; then
    # Ensure no empty if clauses
    :
    #TEA_ADD_SOURCES([win/winFile.c])
    #TEA_ADD_INCLUDES([-I\"$(${CYGPATH} ${srcdir}/win)\"])
else
    # Ensure no empty else clauses
    :
    #TEA_ADD_SOURCES([unix/unixFile.c])
    #TEA_ADD_LIBS([-lsuperfly])
fi

#--------------------------------------------------------------------
# __CHANGE__
# Choose which headers you need.  Extension authors should try very
# hard to only rely on the Tcl public header files.  Internal headers
# contain private data structures and are subject to change without
# notice.
# This MUST be called after TEA_LOAD_TCLCONFIG / TEA_LOAD_TKCONFIG
#--------------------------------------------------------------------

TEA_PUBLIC_TCL_HEADERS
#TEA_PRIVATE_TCL_HEADERS

#TEA_PUBLIC_TK_HEADERS
#TEA_PRIVATE_TK_HEADERS
#TEA_PATH_X

#--------------------------------------------------------------------
# Check whether --enable-threads or --disable-threads was given.
# This auto-enables if Tcl was compiled threaded.
#--------------------------------------------------------------------

TEA_ENABLE_THREADS

#--------------------------------------------------------------------
# The statement below defines a collection of symbols related to
# building as a shared library instead of a static library.
#--------------------------------------------------------------------

TEA_ENABLE_SHARED

#--------------------------------------------------------------------
# This macro figures out what flags to use with the compiler/linker
# when building shared/static debug/optimized objects.  This information
# can be taken from the tclConfig.sh file, but this figures it all out.
#--------------------------------------------------------------------

TEA_CONFIG_CFLAGS

#--------------------------------------------------------------------
# Set the default compiler switches based on the --enable-symbols option.
#--------------------------------------------------------------------

TEA_ENABLE_SYMBOLS

TEABASE_INIT()

#--------------------------------------------------------------------
# This macro generates a line to use when building a library.  It
# depends on values set by the TEA_ENABLE_SHARED, TEA_ENABLE_SYMBOLS,
# and TEA_LOAD_TCLCONFIG macros above.
#--------------------------------------------------------------------

TEA_MAKE_LIB

#--------------------------------------------------------------------
# Determine the name of the tclsh and/or wish executables in the
# Tcl and Tk build directories or the location they were installed
# into. These paths are used to support running test cases only,
# the Makefile should not be making use of these paths to generate
# a pkgIndex.tcl file or anything else at extension build time.
#--------------------------------------------------------------------

TEA_PROG_TCLSH
#TEA_PROG_WISH

#--------------------------------------------------------------------
# Setup a *Config.sh.in configuration file.
#--------------------------------------------------------------------

#TEA_EXPORT_CONFIG([sample])
#AC_SUBST(SAMPLE_VAR)

#--------------------------------------------------------------------
# Specify files to substitute AC variables in. You may alternatively
# have a special pkgIndex.tcl.in or other files which require
# substituting the AC variables in. Include these here.
#--------------------------------------------------------------------

AC_CONFIG_FILES([Makefile pkgIndex.tcl Makefile.teabase])
#AC_CONFIG_FILES([hashConfig.sh])

#--------------------------------------------------------------------
# Finally, substitute all of the various values into the files
# specified with AC_CONFIG_FILES.
#--------------------------------------------------------------------

AC_OUTPUT
