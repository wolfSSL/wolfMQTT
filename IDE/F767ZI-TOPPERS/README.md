# STM32 NUCLEO-F767ZI with TOPPERS OS

This demo uses the STM32 NUCLEO-F767ZI board running the TOPPERS OS to communicate with Azure IoT Central via MQTT.

## This demo requires the following projects

TOPPERS Project:
https://dev.toppers.jp/trac_user/contrib/browser/azure_iot_hub_f767zi/trunk

IDE environment:
https://code.visualstudio.com
Download the compilation environment

MSYS2:
https://www.msys2.org  
 `$ pacman ?Syu`  
 `$ pacman ?Su`  
 `$ pacman -S make`  

ARM Compiler:  
https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads  
 gcc-arm-none-eabi-10-2020-q4-major-win32.exe  

Select the [Extensions] icon [Ctl+Shift+X] in VSCODE
 C/C++ for Visual Studio Code
  Coretex-Debug
  Installation
When you are ready, follow the steps below to create the environment
1. Put wolfmqtt under "trunk-473/" as follows    
  trunk-473/wolfMQTT-master  
2. Put wolfssl under "trunk-473/" as follows(For example, if you want to replace it with the latest version)      
  trunk-473/wolfssl  
3. VSCODE menu    
  [File]->[Add Folder to WorkSpace...]    
  wolfMQTT-master/IDE/F767ZI-TOPPERS  
4. .c_cpp_properties.json  
 "compilerPath": "/Applications/ARM/bin/arm-none-eabi-gcc",    
  Specify the path where you installed your arm-none-eabi-gcc  

 trunk-473/Makefile
 Add  
 `LIBWOLFMQTT = wolfMQTT-master/IDE/F767ZI-TOPPERS/Debug/libwolfmqtt.a`  
 `$(LIBWOLFMQTT):`  
 `$(MAKE) -j -C wolfMQTT-master/IDE/F767ZI-TOPPERS  all`  

 `$(ASP_ELF): $(LIBKERNEL) $(LIBWOLFSSL) $(LIBZLIB) $(LIBAZURE_IOT_SDK)`  
 Change  
 `$(ASP_ELF): $(LIBKERNEL) $(LIBWOLFSSL) $(LIBWOLFMQTT) $(LIBZLIB) $(LIBAZURE_IOT_SDK)`  

 Add  
  refresh:  
 `rm -f $(LIBWOLFMQTT)`  
 clean:  
 `$(MAKE) -j -C wolfMQTT-master/IDE/F767ZI-TOPPERS clean`  
 realclean:  
 `$(MAKE) -j -C wolfMQTT-master/IDE/F767ZI-TOPPERS clean`  

trunk-473/Makefile/app_iothub_client/Debug/Makefile  
 Add  
 `INCLUDES += -I$(SRCDIR)/../wolfMQTT-master/IDE/F767ZI-TOPPERS`  
 `$(SRCDIR)/../wolfMQTT-master/IDE/F767ZI-TOPPERS/Debug/libwolfmqtt.a`  
 `INCLUDES += -I$(SRCDIR)/../wolfMQTT-master/IDE/F767ZI-TOPPERS`  

 trunk-473/wolfssl-4.7.0/user_settings.h  
 `#ifndef HAVE_LIBZ  `  
  `#define HAVE_LIBZ  `  
 `#endif  `  
 delete  

 trunk-473/wolfssl-4.7.0/Makefile  
 Add  
 `C_FLAGS += -D_USE_LONG_TIME_T`  
 `CXX_FLAGS += -D_USE_LONG_TIME_T`  


Change the stack size
 asp_baseplatform/monitor/monitor.h
#define MONITOR_STACK_SIZE 2046 to 4096

app_iothub_client/src/command.c
Add
extern int Wolf_MQTT_main(int argc, char **argv);

app_iothub_client/src/command.c
	{"IOT", iothub_client_main},
Change iothub_client_main to Wolf_MQTT_main

Build
VSCODE Menu
[Terminal]->[Run Task]->[build all]

Writing to the board
[Terminal]->[Run Task]->[write app]

Terminal settings  
 https://ja.osdn.net/projects/ttssh2/  
 Install Tera Term  
 Serial setting of COM3(If it is not in COM3, please check it in system)  
 Setup speed 115200  


Wait for a while to get the time from NTP  
 Sun Dec 12 14:52:18 2021  

Input the following  
 mon>device iot  

Communication will be started.  
