#!/bin/bash
do_cleanup() {
    if  [ $broker_pid != $no_pid ]
    then
        kill -9 $broker_pid
        echo "Killed broker PID $broker_pid"
        broker_pid=$no_pid
    fi

    if  [ $1 -ne 0 ]
    then
        exit 1
    fi
}

generate_port() { # function to produce a random port number
    if [[ "$OSTYPE" == "linux"* ]]; then
        port=$(($(od -An -N2 /dev/urandom) % (65535-49152) + 49152))
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        port=$(($(od -An -N2 /dev/random) % (65535-49152) + 49152))
    else
        echo "Unknown OS TYPE"
        exit 1
    fi
    echo -e "Using port $port"
}

check_broker() {
    timeout 10 sh -c 'until nc -v -z $0 $1; do sleep 1; done' localhost $port
}

# Check for application
[ ! -x ./$prog ] && echo -e "\n\n$name doesn't exist" && exit 1

# Check for TLS support
has_tls=no
./$prog -? 2>&1 | grep -- 'Enable TLS'
if [ $? -eq 0 ]; then
    has_tls=yes
fi
