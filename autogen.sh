#!/bin/sh
#
# Create configure and makefile stuff...
#

set -e

# if get an error about libtool not setup
# " error: Libtool library used but 'LIBTOOL' is undefined
#     The usual way to define 'LIBTOOL' is to add 'LT_INIT' "
# manually call libtoolize or glibtoolize before running this again
# (g)libtoolize

# if you get an error about config.rpath missing, some buggy automake versions
# then touch the missing file (may need to make config/ first).
# touch config/config.rpath
# touch config.rpath


# If this is a source checkout then call autoreconf with error as well
if test -d .git; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi

autoreconf --install --force --verbose 
