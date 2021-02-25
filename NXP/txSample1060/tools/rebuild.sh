# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#!/bin/bash

# Use paths relative to this script's location
SCRIPT=$(readlink -f "$0")
SCRIPTDIR=$(dirname "$SCRIPT")
BASEDIR=$(dirname "$SCRIPTDIR")

# echo $BASEDIR

# If you want to build into a different directory, change this variable
BUILDDIR="$BASEDIR/build"

# Create our build folder if required and clear it
mkdir -p $BUILDDIR
rm -rf $BUILDDIR/*

# Generate the build system using Ninja
cmake -B"$BUILDDIR" -GNinja -DCMAKE_TOOLCHAIN_FILE=$BASEDIR/../../cmake/arm-gcc-cortex-m7-axb.cmake $BASEDIR

# Note different .cmake file above, added --specs=nosys.specs 
# see https://stackoverflow.com/questions/19419782/exit-c-text0x18-undefined-reference-to-exit-when-using-arm-none-eabi-gcc

# Also modified .ld file in the arr/startup dir, added end = __end__ to the .heap section;
# see https://e2e.ti.com/support/tools/ccs/f/81/t/382293?undefined-reference-to-end-in-sbrk-c-in-library-libnosys-a-

# And then do the build
cmake --build $BUILDDIR
