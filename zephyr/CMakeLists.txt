# This module adds its sources to the application, so it has no
# ZEPHYR_CURRENT_LIBRARY. Generate the SBOM with:
#   scripts/sbom-port.sh zephyr --compdb <build>/compile_commands.json
if(CONFIG_WOLFMQTT)
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/zephyr)
  zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})
  FILE(GLOB wolfmqtt_sources ${ZEPHYR_CURRENT_MODULE_DIR}/src/*.c)
  target_sources(app PRIVATE ${wolfmqtt_sources})
  add_definitions(-DWOLFMQTT_ZEPHYR)
endif()
