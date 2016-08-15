# Microchip Harmony wolfMQTT

This example IDE project is meant to be used from inside the Microchip Harmony directory. The configuration.xml files uses relative paths based on the following:

* Library located in `third_party/tcpip/wolfmqtt`
* Application examples located in `apps/tcpip/mqtt_client` and `apps/tcpip/mqtt_firmware`

## Using Examples

* Open the example project in your microchip harmony folder under `apps/tcpip/mqtt_client` or `apps/tcpip/mqtt_firmware`.
* Set project as main project (Right-click on project and choose "Set as Main Project"
* Goto Tools -> Embedded -> MPLab Harmony Configurator
* Open the default system config.
* Configure your BSP.
* Click "Generate Code" button.

## Setting up Harmony
### To add this library to Harmony

* Copy the entire libraries `wolfmqtt` directory into `third_party/tcpip`.
* Copy `wolfmqtt.hconfig` into `third_party/tcpip/config`.
* Add the `wolfmqtt.hconfig` into `tcpip.hconfig`
* Add the following lines into `wolfssl.h.ftl`:

```
<#if CONFIG_USE_3RDPARTY_WOLFMQTT>
#define WOLFMQTT_NONBLOCK

<#if CONFIG_WOLFMQTT_USE_TLS>
#define ENABLE_MQTT_TLS
</#if>
</#if>
```

### Adding example apps to Harmony
* Copy the `mqtt_client` and `mqtt_firmware` directories to `apps/tcpip`