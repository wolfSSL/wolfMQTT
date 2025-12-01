# wolfMQTT for STM32 Cube IDE

The wolfMQTT Cube Pack can be found [here](https://www.wolfssl.com/files/ide/I-CUBE-wolfMQTT.pack).

1. If you intend to use TLS with your wolfMQTT client, the first step is to set up the wolfSSL library in your ST project following the guide here [https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md). If not, skip to the next step.

2. Install the wolfMQTT Cube Pack with the steps below.
    - Run the “STM32CubeMX” tool.
    - Under “Manage software installations” pane on the right, click “INSTALL/REMOVE” button.
    - From Local and choose “I-CUBE-wolfMQTT.pack”.
    - Accept the GPLv3 license. Contact wolfSSL at sales@wolfssl.com for a commercial license and support/maintenance.

3. Create an STM32 project for your board and open the `.ioc` file. Click the `Software Packs` drop down menu and then `Select Components`. Expand the `wolfMQTT` pack and check the Core and Examples components. If you intend to use TLS with you MQTT client, check the TLS component as well. All this will do is enforce the dependency to wolfSSL. To enable TLS support in the wolfMQTT code base, you will have to turn it on in the wolfMQTT settings in the `.ioc` file.

4. In the `Software Packs` configuration category of the `.ioc` file, click on the wolfMQTT pack and enable the library by checking the box.

5. The Pack defaults to using custom IO provided by the user. Modify `IDE/STM32CUBE/userio_template.h` to supply the custom IO. If you'd like to use LwIP instead, configure the wolfMQTT IO settings in the `.ioc` to enable LwIP compatibility. You'll also have to enable LwIP in the `Middleware` configuration category of the project. Make sure that `LWIP_DNS (DNS Module)` is enabled in the LwIP general settings.

6. Save your changes and select yes to the prompt asking about generating code.

7. Build the project.

## Notes
- If building with LwIP and you encounter the error `multiple definition of 'errno'` in `Middlewares/Third_Party/LwIP/system/OS/sys_arch.c`, modify the file as shown below.
```
#if defined(LWIP_SOCKET_SET_ERRNO) && defined(LWIP_PROVIDE_ERRNO)
- int errno;
+ extern int errno;
#endif
```
