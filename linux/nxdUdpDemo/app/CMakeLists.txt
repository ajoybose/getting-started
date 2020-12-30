# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    demo_netx_duo_udp.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} 
    PUBLIC
        azrtos::threadx
        azrtos::netxduo
)

target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        .
)

target_compile_definitions(${PROJECT_NAME} PUBLIC "-D_GNU_SOURCE -DTX_LINUX_DEBUG_ENABLE")

