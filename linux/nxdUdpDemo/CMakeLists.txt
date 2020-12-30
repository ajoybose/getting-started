# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
set(CMAKE_C_STANDARD 99)

set(GSG_BASE_DIR ${CMAKE_SOURCE_DIR}/../..)
set(CORE_SRC_DIR ${GSG_BASE_DIR}/core/src)
set(CORE_LIB_DIR ${GSG_BASE_DIR}/core/lib)

set(CMAKE_TOOLCHAIN_FILE "${GSG_BASE_DIR}/cmake/linux.cmake")
# include(${CMAKE_TOOLCHAIN_FILE})
include(${GSG_BASE_DIR}/cmake/utilities.cmake)

# Define the Project
project(nxd_udp_demo C ASM)

add_compile_definitions(NX_INCLUDE_USER_DEFINE_FILE)

# add_subdirectory(${CORE_SRC_DIR} core_src)
add_subdirectory(lib)
add_subdirectory(app)
add_subdirectory(tx_linux)

