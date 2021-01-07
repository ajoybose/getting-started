set(SOURCES
  # {{BEGIN_TARGET_SOURCES}}
  ${CMAKE_CURRENT_LIST_DIR}/src/nx_pcap_network_driver.c
  ${CMAKE_CURRENT_LIST_DIR}/src/pcap_utils.c
  # {{END_TARGET_SOURCES}}
)

set(INCLUDES
  ${CMAKE_CURRENT_LIST_DIR}/inc
)

set(CFLAGS "-D_GNU_SOURCE -DTX_LINUX_DEBUG_ENABLE")

set(CFLAGSDBG "-D_GNU_SOURCE -DTX_LINUX_DEBUG_ENABLE -DNX_DEBUG -DNX_DEBUG_PACKET")

target_sources(${PROJECT_NAME}_send PRIVATE ${SOURCES})

target_sources(${PROJECT_NAME}_recv PRIVATE ${SOURCES})

target_include_directories(${PROJECT_NAME}_send PUBLIC ${INCLUDES})

target_include_directories(${PROJECT_NAME}_recv PUBLIC ${INCLUDES})

target_compile_definitions(${PROJECT_NAME}_send PUBLIC ${CFLAGS})

target_compile_definitions(${PROJECT_NAME}_recv PUBLIC ${CFLAGSDBG})

