# wolfMQTT for Espressif ESP-IDF

[wolfMQTT](https://www.wolfMQTT.com) provides commercial-grade, world-class encryption libraries to secure connections 
from tiny embedded devices to the largest cloud and super computing platforms. 

Makers and students can use these libraries free of charge, as long as they abide by abide by the terms of GPLV2 licensing. 

Commercial customers are invited to contact wolfSSL for licensing options. 
Visit [wolfSSL.com/Espressif/](https://www.wolfSSL.com/Espressif/) to learn 
more about Espressif-specific development efforts for wolfSSL, wolfMQTT, wolfSSH, and more.

## Getting Started

The easiest way to get started is by using the Espressif Managed Component Registry
at 

The latest experimental development version can be found at the staging site: 
[gojimmypi/mywolfmqtt](https://components-staging.espressif.com/components/gojimmypi/mywolfmqtt/versions/1.0.14-test?language=en).

```
#!/bin/bash

. ~/esp/esp-idf/export.sh

# Needed for Staging site:
export IDF_COMPONENT_REGISTRY_URL=https://components-staging.espressif.com

idf.py create-project-from-example "gojimmypi/mywolfmqtt^1.0.14-test:AWS_IoT_MQTT"

cd AWS_IoT_MQTT

idf.py -p /dev/ttyS9 -b 921600 flash monitor -b 115200

```

## Copy Installation Option

If you wish to _copy_ all the files to the local project component directory,
run `install_wolfMQTT.cmd` from this directory in Windows, Mac or Linux:



#### Linux
```
./install_wolfMQTT.cmd
```

#### Mac
```
./install_wolfMQTT.cmd
```

#### Windows
```
.\install_wolfMQTT.cmd
```

#### WSL
```
./install_wolfMQTT.cmd
```

