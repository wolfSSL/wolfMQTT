# Microchip Harmony wolfMQTT client library and examples

This example IDE project is meant to be used from inside the Microchip Harmony directory. The configuration.xml files uses relative paths based on the following:

* Library located in `third_party/tcpip/wolfmqtt`
* Application examples located in `apps/tcpip/wolfmqtt_client` and `apps/tcpip/wolfmqtt_firmware`

## Using Examples

* Open the example project in your microchip harmony folder under `apps/tcpip/wolfmqtt_client/firmware` or `apps/tcpip/wolfmqtt_firmware/firmware`.
* Set project as main project (Right-click on project and choose "Set as Main Project"
* Goto Tools -> Embedded -> MPLab Harmony Configurator
* Open the default system config.
* Configure your BSP and Ethernet MAC driver.
* Click "Save" button and then "Generate Code" button.

## Setting up Harmony
### To add this library to Harmony

* Copy the entire libraries `wolfmqtt` directory into `third_party/tcpip`.
* Copy `wolfmqtt.hconfig` into `third_party/tcpip/config`.
* Add the `wolfmqtt.hconfig` include into `tcpip.hconfig`
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
* Copy the `wolfmqtt_client` and `wolfmqtt_firmware` directories to `apps/tcpip`
