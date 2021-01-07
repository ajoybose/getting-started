set(SOURCES
  # {{BEGIN_TARGET_SOURCES}}
	${CMAKE_CURRENT_LIST_DIR}/src/tx_initialize_low_level.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_context_restore.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_context_save.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_interrupt_control.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_schedule.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_stack_build.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_system_return.c
	${CMAKE_CURRENT_LIST_DIR}/src/tx_timer_interrupt.c
  # {{END_TARGET_SOURCES}}
)

set(INCLUDES 
  ${CMAKE_CURRENT_LIST_DIR}/inc
)

set(CFLAGS "-D_GNU_SOURCE -DTX_LINUX_DEBUG_ENABLE")

target_sources(${PROJECT_NAME}_send PRIVATE ${SOURCES})

target_sources(${PROJECT_NAME}_recv PRIVATE ${SOURCES})

target_include_directories(${PROJECT_NAME}_send PUBLIC ${INCLUDES})

target_include_directories(${PROJECT_NAME}_recv PUBLIC ${INCLUDES})

target_compile_definitions(${PROJECT_NAME}_send PUBLIC ${CFLAGS})

target_compile_definitions(${PROJECT_NAME}_recv PUBLIC ${CFLAGS})

