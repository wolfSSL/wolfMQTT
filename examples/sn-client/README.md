# MQTT-SN Example
The Sensor Network client implements the MQTT-SN protocol for low-bandwidth networks. There are several differences from MQTT, including the ability to use a two byte Topic ID instead the full topic during subscribe and publish. The SN client requires an MQTT-SN gateway. The gateway acts as an intermediary between the SN clients and the broker. This client was tested with the Eclipse Paho MQTT-SN Gateway, which connects by default to the public Eclipse broker, much like our wolfMQTT Client example. The address of the gateway must be configured as the host. The example is located in `/examples/sn-client/`.

To enable Sensor Network protocol support, configure wolfMQTT using:
`./configure --enable-sn`

## QoS-1
A special feature of MQTT-SN is the ability to use QoS level -1 (negative one) to publish to a predefined topic without first connecting to the gateway. There is no feedback in the application if there was an error, so confirmation of the test would involve running the `sn-client` first and watching for the publish from the `sn-client_qos-1`. There is an example provided in `/examples/sn-client/sn-client_qos-1`. It requires some configuration changes of the gateway.

* Enable the the QoS-1 feature, predefined topics, and change the gateway name in `gateway.conf`:

```
QoS-1=YES
PredefinedTopic=YES
PredefinedTopicList=./predefinedTopic.conf
.
.
.
#GatewayName=PahoGateway-01
GatewayName=WolfGateway
```

* Comment out all entries and add a new topic in `predefinedTopic.conf`:

```
WolfGatewayQoS-1,wolfMQTT/example/testTopic, 1
```

## MQTT-SN with DTLS
MQTT-SN can be secured using DTLS. This enables encryption of sensor data to the gateway. The Eclipse Paho MQTT-SN Gateway supports DTLS clients.

To build the Eclipse Paho MQTT-SN Gateway with DTLS:
`<gateway-folder>/MQTTSNGateway$ ./build.sh dtls`

To build wolfSSL with DTLS support:
`./configure --enable-dtls && make && sudo make install`

To run the wolfMQTT sn-client example with DTLS:
`./examples/sn-client/sn-client -t`

### Notes for Gateway configuration
* To use with local mosquitto broker, edit MQTTSNGateway/gateway.conf. Also set paths to DTLS cert / key.

```
-BrokerName=mqtt.eclipseprojects.io
+BrokerName=localhost

...

-DtlsCertsKey=/etc/ssl/certs/gateway.pem
-DtlsPrivKey=/etc/ssl/private/privkey.pem
+#DtlsCertsKey=/etc/ssl/certs/gateway.pem
+DtlsCertsKey=/<path_to_repo>/wolfssl/certs/server-cert.pem
+#DtlsPrivKey=/etc/ssl/private/privkey.pem
+DtlsPrivKey=/<path_to_repo>/wolfssl/certs/server-key.pem
```
* I had to fix a bug in the gateway (could be related to the openssl or compiler version):

```
diff --git a/MQTTSNGateway/src/linux/dtls/SensorNetwork.cpp b/MQTTSNGateway/src/linux/dtls/SensorNetwork.cpp
index 3f2dcf3..363d0ba 100644
--- a/MQTTSNGateway/src/linux/dtls/SensorNetwork.cpp
+++ b/MQTTSNGateway/src/linux/dtls/SensorNetwork.cpp
@@ -308,7 +308,7 @@ Connections::~Connections()
     {
         for (int i = 0; i < _numfds; i++)
         {
-            if (_ssls[i] > 0)
+            if (_ssls[i] > (SSL *)0)
             {
                 SSL_shutdown(_ssls[i]);
                 SSL_free(_ssls[i]);
@@ -416,7 +416,7 @@ void Connections::close(int index)
         }
     }
 
-    if (ssl > 0)
+    if (ssl > (SSL *)0)
     {
         _numfds--;
         SSL_shutdown(ssl);
```
