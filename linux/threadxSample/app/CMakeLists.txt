# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    sample_threadx.c
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

