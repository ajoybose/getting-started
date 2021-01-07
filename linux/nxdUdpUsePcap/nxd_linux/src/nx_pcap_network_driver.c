// copied and modified from nx_ram_network_driver.c

/* Include necessary system files.  */

#include "nx_api.h"


/* Define the Link MTU. Note this is not the same as the IP MTU.  The Link MTU
   includes the addition of the Physical Network header (usually Ethernet). This
   should be larger than the IP instance MTU by the size of the physical header. */
#define NX_LINK_MTU      1514


/* Define Ethernet address format.  This is prepended to the incoming IP
   and ARP/RARP messages.  The frame beginning is 14 bytes, but for speed
   purposes, we are going to assume there are 16 bytes free in front of the
   prepend pointer and that the prepend pointer is 32-bit aligned.

    Byte Offset     Size            Meaning

        0           6           Destination Ethernet Address
        6           6           Source Ethernet Address
        12          2           Ethernet Frame Type, where:

                                        0x0800 -> IP Datagram
                                        0x0806 -> ARP Request/Reply
                                        0x0835 -> RARP request reply

        42          18          Padding on ARP and RARP messages only.  */

#define NX_ETHERNET_IP   0x0800
#define NX_ETHERNET_ARP  0x0806
#define NX_ETHERNET_RARP 0x8035
#define NX_ETHERNET_IPV6 0x86DD
#define NX_ETHERNET_SIZE 14

extern NX_PACKET_POOL          pool_0;
extern NX_IP                   ip_0;

static ULONG   axb_simulated_address_msw =  0x3232;
static ULONG   axb_simulated_address_lsw =  0x32320606;

unsigned char myMAC[6];

// PCAP Wrapper prototypes
extern int axb_init_pcap(const char* pcInterfaceName);
extern int axb_pcap_send_packet(unsigned char* pucFrame, unsigned short usSize);

// Define driver prototypes.
VOID _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);
static void _nx_pcap_network_driver_output(NX_PACKET *packet_ptr);

void _nx_pcap_network_driver_receive(const unsigned char* pucFrame, unsigned short usSize);


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_pcap_network_driver                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function acts as a virtual network for testing the NetX source */
/*    and driver concepts.   User application may use this routine as     */
/*    a template for the actual network driver.  Note that this driver    */
/*    simulates Ethernet operation.  Some of the parameters don't apply   */
/*    for non-Ethernet interfaces.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP protocol block  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_pcap_network_driver_output         Send physical packet out      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX IP processing                                                  */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
VOID  _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr)
{
// UINT          i = 0;
NX_IP        *ip_ptr;
NX_PACKET    *packet_ptr;
ULONG        *ethernet_frame_ptr;
NX_INTERFACE *interface_ptr;
UINT          interface_index;

    /* Setup the IP pointer from the driver request.  */
    ip_ptr =  driver_req_ptr -> nx_ip_driver_ptr;

    /* Default to successful return.  */
    driver_req_ptr -> nx_ip_driver_status =  NX_SUCCESS;

    /* Setup interface pointer.  */
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;

    /* Obtain the index number of the network interface. */
    interface_index = interface_ptr -> nx_interface_index;

    // Process according to the driver request type in the IP control block.
    switch (driver_req_ptr -> nx_ip_driver_command)
    {

    case NX_LINK_INTERFACE_ATTACH:
    {

#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_INTERFACE_ATTACH - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif
	// alternative .....
	driver_req_ptr->nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
        break;
    }

    case NX_LINK_INTERFACE_DETACH:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_INTERFACE_DETACH - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif
	/*
        // Zero out the driver instance.
        memset(&(nx_ram_driver[i]), 0, sizeof(_nx_pcap_network_driver_instance_type));
	*/
	// alternative .....
	driver_req_ptr->nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
        break;
    }

    case NX_LINK_INITIALIZE:
    {

        /* Device driver shall initialize the Ethernet Controller here. */

#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_INITIALIZE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Once the Ethernet controller is initialized, the driver needs to
           configure the NetX Interface Control block, as outlined below. */

        /* The nx_interface_ip_mtu_size should be the MTU for the IP payload.
           For regular Ethernet, the IP MTU is 1500. */
        nx_ip_interface_mtu_set(ip_ptr, interface_index, (NX_LINK_MTU - NX_ETHERNET_SIZE));

        /* Set the physical address (MAC address) of this IP instance.  */
        /* For this simulated RAM driver, the MAC address is constructed by
           incrementing a base lsw value, to simulate multiple nodes on the
           ethernet.  */
        nx_ip_interface_physical_address_set(ip_ptr, interface_index,
                                             axb_simulated_address_msw,
                                             axb_simulated_address_lsw, NX_FALSE);

        /* Indicate to the IP software that IP to physical mapping is required.  */
        nx_ip_interface_address_mapping_configure(ip_ptr, interface_index, NX_TRUE);

	if (axb_init_pcap("veNet1") != 0) {
	    printf("axb_init_pcap Failed\n");
	}

	unsigned char* pTemp = (unsigned char*) &axb_simulated_address_msw;
	myMAC[0] = pTemp[1];
	myMAC[1] = pTemp[0];
	pTemp = (unsigned char*) &axb_simulated_address_lsw;
	myMAC[2] = pTemp[3];
	myMAC[3] = pTemp[2];
	myMAC[4] = pTemp[1];
	myMAC[5] = pTemp[0];

	break;
    }

    case NX_LINK_UNINITIALIZE:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_UNINITIALIZE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif
	/*
        // Zero out the driver instance. 
        memset(&(nx_ram_driver[i]), 0, sizeof(_nx_pcap_network_driver_instance_type));
	*/
	// alternative .....
	driver_req_ptr->nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
        break;
    }

    case NX_LINK_ENABLE:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_ENABLE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Process driver link enable.  An Ethernet driver shall enable the
           transmit and reception logic.  Once the IP stack issues the
           LINK_ENABLE command, the stack may start transmitting IP packets. */


        /* In the RAM driver, just set the enabled flag.  */
        interface_ptr -> nx_interface_link_up =  NX_TRUE;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Link Enabled - %s\n", ip_ptr -> nx_ip_name);
#endif
        break;
    }

    case NX_LINK_DISABLE:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_DISABLE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Process driver link disable.  This command indicates the IP layer
           is not going to transmit any IP datagrams, nor does it expect any
           IP datagrams from the interface.  Therefore after processing this command,
           the device driver shall not send any incoming packets to the IP
           layer.  Optionally the device driver may turn off the interface. */

        /* In the RAM driver, just clear the enabled flag.  */
        interface_ptr -> nx_interface_link_up =  NX_FALSE;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Link Disabled - %s\n", ip_ptr -> nx_ip_name);
#endif
        break;
    }

    case NX_LINK_PACKET_SEND:
    case NX_LINK_PACKET_BROADCAST:
    case NX_LINK_ARP_SEND:
    case NX_LINK_ARP_RESPONSE_SEND:
    case NX_LINK_RARP_SEND:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_1/5 - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /*
           The IP stack sends down a data packet for transmission.
           The device driver needs to prepend a MAC header, and fill in the
           Ethernet frame type (assuming Ethernet protocol for network transmission)
           based on the type of packet being transmitted.

           The following sequence illustrates this process.
         */


        /* Place the ethernet frame at the front of the packet.  */
        packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

        /* Adjust the prepend pointer.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + NX_ETHERNET_SIZE;

        /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
           bytes to get 32-bit word alignment.  */
        /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
        ethernet_frame_ptr =  (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 2);

        /* Build the ethernet frame.  */
        *ethernet_frame_ptr     =  driver_req_ptr -> nx_ip_driver_physical_address_msw;
        *(ethernet_frame_ptr + 1) =  driver_req_ptr -> nx_ip_driver_physical_address_lsw;
        *(ethernet_frame_ptr + 2) =  (interface_ptr -> nx_interface_physical_address_msw << 16) |
            (interface_ptr -> nx_interface_physical_address_lsw >> 16);
        *(ethernet_frame_ptr + 3) =  (interface_ptr -> nx_interface_physical_address_lsw << 16);

        if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_ARP;
        }
        else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_RESPONSE_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_ARP;
        }
        else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_RARP_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_RARP;
        }
        else if (packet_ptr -> nx_packet_ip_version == 4)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_IP;
        }
        else
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_IPV6;
        }


        /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 1));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 2));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 3));
#ifdef NX_DEBUG_PACKET
        printf("NetX PCAP Driver Packet Send - %s\n", ip_ptr -> nx_ip_name);
#endif

        /* At this point, the packet is a complete Ethernet frame, ready to be transmitted.
           The driver shall call the actual Ethernet transmit routine and put the packet
           on the wire.

           In this example, the simulated RAM network transmit routine is called. */
        // _nx_pcap_network_driver_output(packet_ptr, i);
        _nx_pcap_network_driver_output(packet_ptr);
        break;
    }


    case NX_LINK_MULTICAST_JOIN:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_MULTICAST_JOIN - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif
        break;
    }


    case NX_LINK_MULTICAST_LEAVE:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_MULTICAST_LEAVE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        break;
    }

    case NX_LINK_GET_STATUS:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_STATUS - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link status in the supplied return pointer.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) =  ip_ptr -> nx_ip_interface[0].nx_interface_link_up;
        break;
    }

    case NX_LINK_GET_SPEED:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_SPEED - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_DUPLEX_TYPE:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_DUPLEX_TYPE - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_ERROR_COUNT:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_ERROR_COUNT - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_RX_COUNT:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_RX_COUNT - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_TX_COUNT:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_TX_COUNT - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_ALLOC_ERRORS:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_GET_ALLOC_ERRORS - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_DEFERRED_PROCESSING:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_DEFERRED_PROCESSING - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Driver defined deferred processing. This is typically used to defer interrupt
           processing to the thread level.

           A typical use case of this command is:
           On receiving an Ethernet frame, the RX ISR does not process the received frame,
           but instead records such an event in its internal data structure, and issues
           a notification to the IP stack (the driver sends the notification to the IP
           helping thread by calling "_nx_ip_driver_deferred_processing()".  When the IP stack
           gets a notification of a pending driver deferred process, it calls the
           driver with the NX_LINK_DEFERRED_PROCESSING command.  The driver shall complete
           the pending receive process.
         */

        /* The simulated RAM driver doesn't require a deferred process so it breaks out of
           the switch case. */


        break;
    }

    case NX_LINK_SET_PHYSICAL_ADDRESS:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_LINK_SET_PHYSICAL_ADDRESS - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif
        break;
    }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    case NX_INTERFACE_CAPABILITY_GET:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_INTERFACE_CAPABILITY_GET - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Return the capability of the Ethernet controller speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_INTERFACE_CAPABILITY_SET:
    {
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: NX_INTERFACE_CAPABILITY_SET - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Set the capability of the Ethernet controller. Unsupported feature.  */
        break;
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY  */

    default:
#ifdef NX_DEBUG
        printf("_nx_pcap_network_driver: default - IP: %#10lX - Name: %s\n", ip_ptr -> nx_ip_address, ip_ptr -> nx_ip_name);
#endif

        /* Invalid driver request.  */

        /* Return the unhandled command status.  */
        driver_req_ptr -> nx_ip_driver_status =  NX_UNHANDLED_COMMAND;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Received invalid request - %s\n", ip_ptr -> nx_ip_name);
#endif
        break;
    }
}




// function to send packet contents out via PCAP utils
// copied extensively from _nx_ram_network_driver_output()
void  _nx_pcap_network_driver_output(NX_PACKET *packet_ptr)
{

  UINT       old_threshold = 0;
  UINT       i;

#ifdef NX_DEBUG_PACKET
  UCHAR *ptr;
  UINT   j;

    ptr =  packet_ptr -> nx_packet_prepend_ptr;
    printf("Ethernet Packet: ");
    for (j = 0; j < 6; j++)
    {
        printf("%02X", *ptr++);
    }
    printf(" ");
    for (j = 0; j < 6; j++)
    {
        printf("%02X", *ptr++);
    }
    printf(" %02X", *ptr++);
    printf("%02X ", *ptr++);

    i = 0;
    for (j = 0; j < (packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE); j++)
    {
        printf("%02X", *ptr++);
        i++;
        if (i > 3)
        {
            i = 0;
            printf(" ");
        }
    }
    printf("\n");


#endif

    // Disable preemption. 
    tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

    if (axb_pcap_send_packet(packet_ptr->nx_packet_prepend_ptr, packet_ptr->nx_packet_length) != 0) {
      printf("axb_pcap_send_packet Failed\n");
    }
    // Remove the Ethernet header.  In real hardware environments, this is typically done after a transmit complete interrupt.
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    // Adjust the packet length.
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

    // Now that the Ethernet frame has been removed, release the packet.
    nx_packet_transmit_release(packet_ptr);

    // Restore preemption.
    // lint -e{644} suppress variable might not be initialized, since "old_threshold" was initialized in previous tx_thread_preemption_change.
    tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
}




// callback function from PCAP utils to deliver packet contents
// copied extensively from _nx_ram_network_driver_receive()
void _nx_pcap_network_driver_receive(const unsigned char* pucFrame, unsigned short usSize) {
  UINT status;
  NX_PACKET *packet_ptr;
  UINT packet_type;

  //get packet buffer from packet pool1
  status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_NO_WAIT);
  if (status != NX_SUCCESS) {
    printf("_nx_pcap_network_driver_receive(): nx_packet_allocate call failed\n");
    return;
  }
			      
  packet_type =  (((UINT)(*(pucFrame + 12))) << 8) | ((UINT)(*(pucFrame + 13)));


  if (packet_type == NX_ETHERNET_IP)
  {
    packet_ptr->nx_packet_length = usSize;
    // word align IP Header
//    packet_ptr->nx_packet_prepend_ptr += 2;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + usSize;

    memcpy(packet_ptr->nx_packet_prepend_ptr, pucFrame, usSize);
    
    // Clean off the Ethernet header. 
    packet_ptr->nx_packet_prepend_ptr =  packet_ptr->nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr->nx_packet_length =  packet_ptr->nx_packet_length - NX_ETHERNET_SIZE;

#ifdef NX_DEBUG_PACKET
    printf("NetX PCAP Driver IP Packet Receive - %s\n", ip_0.nx_ip_name);
#endif

    _nx_ip_packet_receive(&ip_0, packet_ptr);
  }
  else if (packet_type == NX_ETHERNET_ARP)
  {

    packet_ptr->nx_packet_length = usSize;
    // word align IP Header
//    packet_ptr->nx_packet_prepend_ptr += 2;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + usSize;

    memcpy(packet_ptr->nx_packet_prepend_ptr, pucFrame, usSize);
    
    // Clean off the Ethernet header. 
    packet_ptr->nx_packet_prepend_ptr =  packet_ptr->nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr->nx_packet_length =  packet_ptr->nx_packet_length - NX_ETHERNET_SIZE;

#ifdef NX_DEBUG
    printf("NetX PCAP Driver ARP Receive - %s\n", ip_0.nx_ip_name);
#endif
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);
  }
  else if (packet_type == NX_ETHERNET_RARP)
  {
    packet_ptr->nx_packet_length = usSize;
    // word align IP Header
//    packet_ptr->nx_packet_prepend_ptr += 2;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + usSize;

    memcpy(packet_ptr->nx_packet_prepend_ptr, pucFrame, usSize);
    
    // Clean off the Ethernet header. 
    packet_ptr->nx_packet_prepend_ptr =  packet_ptr->nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr->nx_packet_length =  packet_ptr->nx_packet_length - NX_ETHERNET_SIZE;

#ifdef NX_DEBUG
    printf("NetX PCAP Driver RARP Receive - %s\n", ip_0.nx_ip_name);
#endif
    _nx_rarp_packet_deferred_receive(&ip_0, packet_ptr);
  }
  else
  {
    printf("NetX PCAP Driver Received Unknown Packet Type - %u\n", packet_type);
    nx_packet_release(packet_ptr);
  }

}



