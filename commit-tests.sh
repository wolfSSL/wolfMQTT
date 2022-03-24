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

# make sure MQTTv5 is okay
echo -e "\n\nTesting MQTTv5...\n\n"
./configure --enable-v5;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --v5' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-v5' make test failed " && exit 1


# make sure multithread is okay
echo -e "\n\nTesting multithread config...\n\n"
./configure --enable-mt;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mt' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mt' make test failed " && exit 1

# make sure enable-all is okay
echo -e "\n\nTesting enable-all config...\n\n"
./configure --enable-all;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-all' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-all' make test failed " && exit 1

# make sure multithread with non-blocking is okay
echo -e "\n\nTesting multithread with non-block config...\n\n"
./configure --enable-mt --enable-nonblock CFLAGS="-DWOLFMQTT_TEST_NONBLOCK";
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mt --enable-nonblock' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-mt --enable-nonblock' make test failed " && exit 1

# make sure non-blocking plus TLS is okay
echo -e "\n\nTesting Non-Blocking TLS config as well...\n\n"
./configure --enable-nonblock --enable-tls CFLAGS="-DWOLFMQTT_TEST_NONBLOCK";
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --enable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --enable-tls' make test failed " && exit 1

# make sure non-blocking is okay
echo -e "\n\nTesting Non-Blocking config too...\n\n"
./configure --enable-nonblock --disable-tls CFLAGS="-DWOLFMQTT_TEST_NONBLOCK";
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --disable-tls' failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nTest './configure --enable-nonblock --disable-tls' make test failed " && exit 1

exit 0
