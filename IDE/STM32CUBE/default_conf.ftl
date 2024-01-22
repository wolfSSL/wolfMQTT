[#ftl]
/**
  ******************************************************************************
  * File Name          : ${name}
  * Description        : This file provides code for the configuration
  *                      of the ${name} instances.
  ******************************************************************************
[@common.optinclude name=mxTmpFolder+"/license.tmp"/][#--include License text --]
  ******************************************************************************
  */
[#assign s = name]
[#assign toto = s?replace(".","_")]
[#assign toto = toto?replace("/","")]
[#assign toto = toto?replace("-","_")]
[#assign inclusion_protection = toto?upper_case]
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __${inclusion_protection}__
#define __${inclusion_protection}__

#ifdef __cplusplus
 extern "C" {
#endif


/* Includes ------------------------------------------------------------------*/
[#if includes??]
[#list includes as include]
#include "${include}"
[/#list]
[/#if]

[#-- SWIPdatas is a list of SWIPconfigModel --]  
[#list SWIPdatas as SWIP]  
[#-- Global variables --]
[#if SWIP.variables??]
	[#list SWIP.variables as variable]
extern ${variable.value} ${variable.name};
	[/#list]
[/#if]

[#-- Global variables --]

[#assign instName = SWIP.ipName]   
[#assign fileName = SWIP.fileName]   
[#assign version = SWIP.version]   

/**
	MiddleWare name : ${instName}
	MiddleWare fileName : ${fileName}
	MiddleWare version : ${version}
*/
[#if SWIP.defines??]
	[#list SWIP.defines as definition]	
/*---------- [#if definition.comments??]${definition.comments}[/#if] -----------*/
#define ${definition.name} #t#t ${definition.value} 
[#if definition.description??]${definition.description} [/#if]
	[/#list]
[/#if]



[/#list]

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFMQTT_STM32_CUBEMX
#define NO_FILESYSTEM
#define WOLFMQTT_NO_STDIN_CAP

/* ------------------------------------------------------------------------- */
/* Operating System */
/* ------------------------------------------------------------------------- */
#if defined(WOLFMQTT_CONF_FREERTOS) && WOLFMQTT_CONF_FREERTOS == 1
    #define FREERTOS
#endif

/* ------------------------------------------------------------------------- */
/* Enable/Disable Features */
/* ------------------------------------------------------------------------- */
/* TLS */
#undef ENABLE_MQTT_TLS
#if defined(WOLFMQTT_CONF_TLS) && WOLFMQTT_CONF_TLS == 1
	#define ENABLE_MQTT_TLS
#endif

/* MQTT v5 */
#undef WOLFMQTT_V5
#if defined(WOLFMQTT_CONF_V5) && WOLFMQTT_CONF_V5 == 1
	#define WOLFMQTT_V5
#endif

/* TIMEOUT */
#undef WOLFMQTT_NO_TIMEOUT
#if !defined(WOLFMQTT_CONF_TIMEOUT) || WOLFMQTT_CONF_TIMEOUT == 0
	#define WOLFMQTT_NO_TIMEOUT
#endif

/* THREADING */
#undef WOLFMQTT_MULTITHREAD
#if defined(WOLFMQTT_CONF_MULTITHREAD) && WOLFMQTT_CONF_MULTITHREAD == 1
    #ifdef FREERTOS
        #define WOLFMQTT_MULTITHREAD
    #else
        #error "FREERTOS required to enable multi-threading"
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* wolfMQTT IO */
/* ------------------------------------------------------------------------- */
#if defined(WOLFMQTT_CONF_IO) && WOLFMQTT_CONF_IO == 2
    #define WOLFSSL_LWIP
#else
    #define WOLFMQTT_USER_IO
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLFMQTT_CONF_DEBUG) && WOLFMQTT_CONF_DEBUG == 1
    #define DEBUG_WOLFMQTT
#endif


typedef unsigned int size_t;

#define NO_MAIN_DRIVER

#ifdef WOLFSSL_LWIP
    #define HAVE_SOCKET
#endif

#ifdef __cplusplus
}
#endif
#endif /* ${inclusion_protection}_H */

/**
  * @}
  */

/*****END OF FILE****/
