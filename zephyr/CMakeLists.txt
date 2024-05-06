if(CONFIG_WOLFMQTT)
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/zephyr)
  zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})
  FILE(GLOB wolfmqtt_sources ${ZEPHYR_CURRENT_MODULE_DIR}/src/*.c)
  target_sources(app PRIVATE ${wolfmqtt_sources})
  add_definitions(-DWOLFMQTT_ZEPHYR)

  if(CONFIG_WOLFMQTT_SETTINGS_FILE)
      target_compile_definitions(wolfmqtt INTERFACE
        WOLFMQTT_SETTINGS_FILE="${CONFIG_WOLFMQTT_SETTINGS_FILE}"
      )
    endif()
endif()
