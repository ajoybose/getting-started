# Getting Started with Azure RTOS and Azure IoT - This Fork

The sub-directories herein contain the cmake buildable: 

## [ThreadX](https://github.com/azure-rtos/threadx) sample 

Building and executing sample_threadx.c.

### Build

In the threadxSample/tools run the build.sh script

### Execute

After building, in threadxSample/build/app, run tx_sample


## [netxduo](https://github.com/azure-rtos/netxduo) sample 

Building and executing demo_netx_duo_udp.c.

### Build

In the nxdUdpDemo/tools run the build.sh script

### Execute

After building, in nxdYdpDemo/build/app, run nxd_udp_demo


## [netxduo](https://github.com/azure-rtos/netxduo) sample modified to use libpcap

Modified demo_netx_duo_udp, and used nx_ram_network_driver.c to create nx_pcap_network_driver.c.

Created pcap_utils.c with functions that wrap the libpcap functions.

### Install

Needs the x86 version of libpcap, so on Ubuntu,

sudo apt-get install libpcap-dev:i386


### Build

In the nxdUdpUsePcap/tools run the build.sh script

### Execute

Testing was done using Linux Network Namespaces.

In nxdUdpUsePcap/tools, run mkns.sh to create the 4 namespaces and all devices that will be used.

After building, in nxdUdpUsePcap/tools, run the send.sh script

In another terminal, in nxdUdpUsePcap/tools, run rx.sh, it runs the python script that sends and receives packets from the executable.

As for the app_recv sub-directory, the intention was different, but it now serves as an executable with debug on for the 'driver' code.


## Notes

Most of the code was hacked together to understand how to build and use ThreadX and NetXDuo over the Christmas 2020 and New Years 2021 weekends, and other evenings. Created as notes to self mainly, so I can pick up where I left off. Obviously, this is NOT production quality code or even clean code, it just runs, and should not be used for anything other than self-education. If you find it helpful or have any suggestions/corrections, please leave a note. I'm learning this myself. 

Cheers!




