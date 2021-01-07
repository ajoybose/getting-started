# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    demo_netx_duo_udp.c
)

find_library(PCAPLib libpcap.a PATHS /usr/lib/i386-linux-gnu)

add_executable(${PROJECT_NAME}_send ${SOURCES})

target_link_libraries(${PROJECT_NAME}_send 
    PUBLIC
        azrtos::threadx
        azrtos::netxduo
        ${PCAPLib}
)

target_include_directories(${PROJECT_NAME}_send 
    PUBLIC 
        .
)

target_compile_definitions(${PROJECT_NAME}_send PUBLIC "-D_GNU_SOURCE -DTX_LINUX_DEBUG_ENABLE")

