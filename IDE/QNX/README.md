WOLFSSL_DIR is used to point to the directory where wolfSSL was built. By default it looks for an adjacent 'wolfssl' directory. i.e.

```
mkdir test
cd test
git clone https://github.com/wolfssl/wolfssl
git clone https://github.com/wolfssl/wolfmqtt
```

Then both projects can be imported as an momentics IDE project. To first build wolfSSL view the README located at wolfssl/IDE/QNX/README.md. Then to build wolfMQTT start momentics with the workspace located at wolfmqtt/IDE/QNX/. Import the wolfmqtt project (File->Import->General->Existing Projects into Workspace, in "Select root directory" browse to the directory wolfmqtt/IDE/QNX/ and select the wolfmqtt project then click "Finish".

To alter the location that the wolfSSL directory is set WOLFSSL_DIR as an env. variable.

```
export WOLFSSL_DIR=/my/wolfssl/directory/
```

To build from the command line using the Makefile do the following:

```
source ~/qnx710/qnxsdp-env.sh
cd wolfmqtt/IDE/QNX/wolfmqtt
make
```
