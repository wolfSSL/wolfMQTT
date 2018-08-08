#!/bin/sh

#commit-tests.sh


# make sure current config is ok
echo -e "\n\nTesting current config...\n\n"
make clean; make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCurrent config make test failed" && exit 1


# make sure basic config is ok
echo -e "\n\nTesting no TLS config too...\n\n"
./configure --disable-tls;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --disable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --disable-tls' make test failed " && exit 1

# make sure basic config plus tls is ok
echo -e "\n\nTesting TLS config too...\n\n"
./configure --enable-tls;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-tls' make test failed " && exit 1

# make sure non-blocking is okay
echo -e "\n\nTesting Non-Blocking config too...\n\n"
./configure --enable-nonblock --disable-tls;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --disable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --disable-tls' make test failed " && exit 1


# make sure non-blocking plus TLS is okay
echo -e "\n\nTesting Non-Blocking TLS config as well...\n\n"
./configure --enable-nonblock --enable-tls;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --enable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --enable-tls' make test failed " && exit 1


# make sure mqtt5 with property callback is okay
echo -e "\n\nTesting mqtt5 with property callback config additionally...\n\n"
./configure --enable-mqtt5 --enable-propcb;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mqtt5 --enable-propcb' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mqtt5 --enable-propcb' make test failed " && exit 1

exit 0
