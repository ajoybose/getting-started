# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#!/bin/bash

# Use paths relative to this script's location
SCRIPT=$(readlink -f "$0")
SCRIPTDIR=$(dirname "$SCRIPT")
BASEDIR=$(dirname "$SCRIPTDIR")

# echo $BASEDIR

# Build directory
BUILDDIR="$BASEDIR/build"

# Execute Binary
sudo ip netns exec net1 $BUILDDIR/app_send/nxd_udp_use_pcap_send

