# wolfmqtt
# Copyright (C) 2018 wolfSSL Inc.
# All right reserved.

AC_COPYRIGHT([Copyright (C) 2014-2018 wolfSSL Inc.])
AC_INIT([wolfmqtt],[1.2.0],[https://github.com/wolfssl/wolfMQTT/issues],[wolfmqtt],[http://www.wolfssl.com])

AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])

# The following sets CFLAGS to empty if unset on command line.
: ${CFLAGS=""}

# Test ar for the "U" option. Should be checked before the libtool macros.
xxx_ar_flags=$((ar --help) 2>&1)
AS_CASE([$xxx_ar_flags],[*'use actual timestamps and uids/gids'*],[: ${AR_FLAGS="Ucru"}])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])

AC_ARG_PROGRAM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

WOLFMQTT_LIBRARY_VERSION=4:0:0
#                        | | |
#                 +------+ | +---+
#                 |        |     |
#                current:revision:age
#                 |        |     |
#                 |        |     +- increment if interfaces have been added
#                 |        |        set to zero if interfaces have been removed
#                 |        |        or changed
#                 |        +- increment if source code has changed
#                 |           set to zero if current is incremented
#                 +- increment if interfaces have been added, removed or changed
AC_SUBST([WOLFMQTT_LIBRARY_VERSION])


LT_PREREQ([2.2])
LT_INIT([disable-static], [win32-dll])
LT_LANG([C])

gl_VISIBILITY
AS_IF([test -n "$CFLAG_VISIBILITY"],
      [AM_CPPFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"
       CPPFLAGS="$CPPFLAGS $CFLAG_VISIBILITY"])

# silent
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_SIZEOF([long long], 8)
AC_CHECK_SIZEOF([long], 4)

# Check headers/libs
AC_CHECK_FUNCS([gethostbyname getaddrinfo gettimeofday inet_ntoa memset socket signal])
AC_CHECK_LIB([network],[socket])

# DEBUG
DEBUG_CFLAGS="-g -O0 -DDEBUG_WOLFMQTT"

# Optimizations
OPTIMIZE_CFLAGS="-O2"

AX_DEBUG
AS_IF([test "x$ax_enable_debug" = "xyes" || test "x$ax_enable_debug" = "xverbose"],
      [AM_CFLAGS="$DEBUG_CFLAGS $AM_CFLAGS -DDEBUG"],
      [AM_CFLAGS="$AM_CFLAGS $OPTIMIZE_CFLAGS -DNDEBUG"])


AX_PTHREAD([
    # If AX_PTHREAD is adding -Qunused-arguments, need to prepend with
    # -Xcompiler libtool will use it. Newer versions of clang don't need
    # the -Q flag when using pthreads.
    AS_CASE([$PTHREAD_CFLAGS],[-Qunused-arguments*],[PTHREAD_CFLAGS="-Xcompiler $PTHREAD_CFLAGS"])
    AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"])


# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
   AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi


# Verbose Logging
if test "x$ax_enable_debug" = "xverbose"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_DEBUG_CLIENT -DWOLFMQTT_DEBUG_SOCKET"
fi


# TLS Support with wolfSSL
# Examples, used to disable examples
AC_ARG_ENABLE([tls],
    [AS_HELP_STRING([--enable-tls],[Enable TLS support with wolfSSL  (default: enabled)])],
    [ ENABLED_TLS=$enableval ],
    [ ENABLED_TLS=yes ]
    )

if test "x$ENABLED_TLS" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DENABLE_MQTT_TLS"

    TAO_REQUIRE_LIBWOLFSSL
fi
AM_CONDITIONAL([HAVE_LIBWOLFSSL], [test "x$ENABLED_TLS" = "xyes"])


# Non-Blocking support
AC_ARG_ENABLE([nonblock],
    [AS_HELP_STRING([--enable-nonblock],[Enable non-blocking support  (default: disabled)])],
    [ ENABLED_NONBLOCK=$enableval ],
    [ ENABLED_NONBLOCK=no ]
    )

if test "x$ENABLED_NONBLOCK" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_NONBLOCK"
fi


# Timeout support
AC_ARG_ENABLE([timeout],
    [AS_HELP_STRING([--enable-timeout],[Enable timeout support  (default: enabled)])],
    [ ENABLED_TIMEOUT=$enableval ],
    [ ENABLED_TIMEOUT=yes ]
    )

if test "x$ENABLED_TIMEOUT" = "xno"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_NO_TIMEOUT"
fi

# Examples
AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples],[Enable examples (default: enabled)])],
    [ ENABLED_EXAMPLES=$enableval ],
    [ ENABLED_EXAMPLES=yes ]
    )

AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$ENABLED_EXAMPLES" = "xyes"])


# Error strings 
AC_ARG_ENABLE([errorstrings],
    [AS_HELP_STRING([--enable-errorstrings],[Enable error strings  (default: enabled)])],
    [ ENABLED_ERROR_STRINGS=$enableval ],
    [ ENABLED_ERROR_STRINGS=yes ]
    )

if test "x$ENABLED_ERROR_STRINGS" = "xno"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_NO_ERROR_STRINGS"
fi


# STDIN / FGETS for examples
AC_ARG_ENABLE([stdincap],
    [AS_HELP_STRING([--enable-stdincap],[Enable examples STDIN capture  (default: enabled)])],
    [ ENABLED_STDINCAP=$enableval ],
    [ ENABLED_STDINCAP=yes ]
    )

if test "x$ENABLED_STDINCAP" = "xno"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_NO_STDIN_CAP"
fi

AM_CONDITIONAL([BUILD_STDINCAP], [test "x$ENABLED_STDINCAP" = "xyes"])


# MQTT-SN Sensor Network
AC_ARG_ENABLE([sn],
    [AS_HELP_STRING([--enable-sn],[Enable MQTT-SN support (default: disabled)])],
    [ ENABLED_SN=$enableval ],
    [ ENABLED_SN=no ]
    )

if test "x$ENABLED_SN" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_SN"
fi

AM_CONDITIONAL([BUILD_SN], [test "x$ENABLED_SN" = "xyes"])

# MQTT v5.0
AC_ARG_ENABLE([mqtt5],
    [AS_HELP_STRING([--enable-mqtt5],[Enable MQTT v5.0 support (default: disabled)])],
    [ ENABLED_MQTTV50=$enableval ],
    [ ENABLED_MQTTV50=no ]
    )

if test "x$ENABLED_MQTTV50" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_V5"
fi

AM_CONDITIONAL([BUILD_MQTT5], [test "x$ENABLED_MQTTV50" = "xyes"])

# Property callback
AC_ARG_ENABLE([propcb],
    [AS_HELP_STRING([--enable-propcb],[Enable property callback (v5 only) (default: disabled)])],
    [ ENABLED_PROPCB=$enableval ],
    [ ENABLED_PROPCB=no ]
    )

if test "x$ENABLED_PROPCB" = "xyes"
then
    if test "x$ENABLED_MQTTV50" = "xno"
    then
        AC_MSG_ERROR([cannot enable propcb without enabling mqtt5.])
    fi
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_PROPERTY_CB"
fi


# Disconnect callback
AC_ARG_ENABLE([discb],
    [AS_HELP_STRING([--enable-discb],[Enable disconnect callback (default: enabled)])],
    [ ENABLED_DISCB=$enableval ],
    [ ENABLED_DISCB=yes ]
    )

if test "x$ENABLED_DISCB" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFMQTT_DISCONNECT_CB"
fi



# HARDEN FLAGS
AX_HARDEN_CC_COMPILER_FLAGS

OPTION_FLAGS="$CFLAGS $CPPFLAGS $AM_CFLAGS"

CREATE_HEX_VERSION
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

# FINAL
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([wolfmqtt/version.h])
AC_CONFIG_FILES([wolfmqtt/options.h])

AX_CREATE_GENERIC_CONFIG
AX_AM_JOBSERVER([yes])

AC_OUTPUT

# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1
echo

# generate user options header
echo "---"
echo "Generating user options header..."

OPTION_FILE="wolfmqtt/options.h"
rm -f $OPTION_FILE

echo "/* wolfmqtt options.h" > $OPTION_FILE
echo " * generated from configure options" >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * Copyright (C) 2006-2018 wolfSSL Inc." >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * * This file is part of wolfMQTT." >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " */" >> $OPTION_FILE

echo "" >> $OPTION_FILE
echo "#ifndef WOLFMQTT_OPTIONS_H" >> $OPTION_FILE
echo "#define WOLFMQTT_OPTIONS_H" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "extern \"C\" {" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE

for option in $OPTION_FLAGS; do
    defonly=`echo $option | sed 's/-D//'`
    if test "$defonly" != "$option"
    then
        noequalsign=`echo $defonly | sed 's/=/ /'`
        if test "$noequalsign" = "NDEBUG" || test "$noequalsign" = "DEBUG"
        then
            echo "not outputting (N)DEBUG to $OPTION_FILE"
            continue
        fi

        # allow user to igonore system options
        ignoresys=no
        if [[[ $noequalsign == _* ]]] ;
        then
            ignoresys=yes
            echo "#ifndef WOLFSSL_OPTIONS_IGNORE_SYS" >> $OPTION_FILE
        fi

        noarg=`echo $defonly | sed 's/=.*//'`
        echo "#undef  $noarg" >> $OPTION_FILE
        echo "#define $noequalsign" >> $OPTION_FILE

        if test "$ignoresys" = "yes"
        then
            echo "#endif" >> $OPTION_FILE
        fi

        echo "" >> $OPTION_FILE
    else
        echo "option w/o begin -D is $option, not saving to $OPTION_FILE"
    fi
done

echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "}" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#endif /* WOLFMQTT_OPTIONS_H */" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo

# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC"
echo "   * C Flags:                   $CFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * Linker Flags:              $LDFLAGS"
echo "   * LIB Flags:                 $LIB"

echo "   * Disconnect Callback:       $ENABLED_DISCB"
echo "   * Error Strings:             $ENABLED_ERROR_STRINGS"
echo "   * Enable MQTT-SN:            $ENABLED_SN"
echo "   * Enable MQTT v5.0:          $ENABLED_MQTTV50"
echo "   * Property Callback:         $ENABLED_PROPCB"
echo "   * Examples:                  $ENABLED_EXAMPLES"
echo "   * Non-Blocking:              $ENABLED_NONBLOCK"
echo "   * STDIN Capture:             $ENABLED_STDINCAP"
echo "   * TLS:                       $ENABLED_TLS"

