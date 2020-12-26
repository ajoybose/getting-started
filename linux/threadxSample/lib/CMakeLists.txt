# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Define ThreadX user configuration
set(TX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/threadx/tx_user.h" CACHE STRING "Enable TX user configuration")

# Define NetXDuo user configuration
set(NX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/netxduo/nx_user.h" CACHE STRING "Enable NX user configuration")


# Core libraries
add_subdirectory(${CORE_LIB_DIR}/threadx threadx)
add_subdirectory(${CORE_LIB_DIR}/netxduo netxduo)

