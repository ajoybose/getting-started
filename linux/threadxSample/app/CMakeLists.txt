# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    sample_threadx.c
	src/tx_initialize_low_level.c
	src/tx_thread_context_restore.c
	src/tx_thread_context_save.c
	src/tx_thread_interrupt_control.c
	src/tx_thread_schedule.c
	src/tx_thread_stack_build.c
	src/tx_thread_system_return.c
	src/tx_timer_interrupt.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} 
    PUBLIC
        azrtos::threadx
        azrtos::netxduo
)

target_include_directories(${PROJECT_NAME} 
    PUBLIC 
    inc
        .
)

# create_bin_output(${PROJECT_NAME})
# firmware_size(${PROJECT_NAME})
