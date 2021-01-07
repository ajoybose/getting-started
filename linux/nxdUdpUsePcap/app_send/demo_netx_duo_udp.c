// modified version of demo_netx_duo_udp.c
// only Sends UDP Packets out using the pcap network driver instead

#include   "tx_api.h"
#include   "nx_api.h"
#include   <stdio.h>

#define     DEMO_STACK_SIZE 2048
#define     DEMO_DATA       "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define     PACKET_SIZE     1536
#define     POOL_SIZE       ((sizeof(NX_PACKET) + PACKET_SIZE) * 16)

#define AXB_IP_HEADER_SIZE 20
#define AXB_UDP_HEADER_SIZE 8


/* Define the ThreadX and NetX object control blocks...  */

TX_THREAD               thread_0;
TX_THREAD               thread_1;
TX_THREAD               thread_2;

NX_PACKET_POOL          pool_0;
NX_IP                   ip_0;
NX_IP                   ip_1;


NX_UDP_SOCKET           socket_0;
NX_UDP_SOCKET           socket_1;
UCHAR                   pool_buffer[POOL_SIZE];


/* Define the counters used in the demo application...  */

static ULONG error_counter;

/* Define thread prototypes.  */

void thread_0_entry(ULONG thread_input);
void thread_1_entry(ULONG thread_input);
void thread_2_entry(ULONG thread_input);

extern void _nx_pcap_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern int axb_pcap_loop(const char* if_name);

/* Define main entry point.  */

int main()
{
    printf("In main()\n");
    error_counter = 0;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
    
    printf("Leaving main()\n");
}


/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

CHAR *pointer;
UINT  status;

    printf("In tx_application_define(), error counter = %lu\n", error_counter);
    /* Setup the working pointer.  */
    pointer =  (CHAR *)first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    


    /* .  */
    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_buffer, POOL_SIZE);

    /* Check for pool creation error.  */
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): pool pool_0 creation error, error counter = %lu\n", error_counter);
    }

    /* Create an IP instance.  */
    // status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_pcap_network_driver,
    //                       pointer, 2048, 1);
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 4, 5), 0xFFFFFF00UL, &pool_0, _nx_pcap_network_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    // Check for IP create error.  
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): IP create ip_0 error, error counter = %lu\n", error_counter);
    }

    /*
    // Create another IP instance.
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_pcap_network_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    // Check for IP create error.  
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): IP create ip_1 error, error counter = %lu\n", error_counter);
    }
    */

    // Enable ARP and supply ARP cache memory for IP Instance 0.  
    status =  nx_arp_enable(&ip_0, (void *)pointer, 1024);
    pointer = pointer + 1024;
    // Check for ARP enable error.  
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): ARP enable ip_0 error, error counter = %lu\n", error_counter);
    }
    /*
    // Enable ARP and supply ARP cache memory for IP Instance 1.  
    status =  nx_arp_enable(&ip_1, (void *)pointer, 1024);
    pointer = pointer + 1024;
    // Check for ARP enable error. 
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): ARP enable ip_1 error, error counter = %lu\n", error_counter);
    }
    */
    // Enable ICMP 
    status = nxd_icmp_enable(&ip_0);
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): Enable ICMP ip_0 error, error counter = %lu\n", error_counter);
    }
    /*
    status = nxd_icmp_enable(&ip_1);
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): Enable ICMP ip_1 error, error counter = %lu\n", error_counter);
    }
    */
    // Enable UDP traffic.  
    status =  nx_udp_enable(&ip_0);
    // Check for UDP enable error.  
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): UDP enable ip_0 error, error counter = %lu\n", error_counter);
    }
    /*
    status = nx_udp_enable(&ip_1);
    // Check for UDP enable error. 
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): UDP enable ip_1 error, error counter = %lu\n", error_counter);
    }
    */
    // Enable TCP traffic.  
    status =  nx_tcp_enable(&ip_0);
    // Check for UDP enable error.  
    if (status)
    {
        error_counter++;
	printf("tx_application_define(): TCP enable ip_0 error, error counter = %lu\n", error_counter);
    }
    printf("Leaving tx_application_define(), error counter = %lu\n", error_counter);
}



/* Define the test threads.  */

void thread_0_entry(ULONG thread_input)
{

  UINT       status;
  NX_PACKET *my_packet;
  NXD_ADDRESS ipv4_address;
  printf("In thread_0_entry(), error counter = %lu\n", error_counter);

  NX_PARAMETER_NOT_USED(thread_input);

  /* Let the IP threads and thread 1 execute.    */
  tx_thread_sleep(NX_IP_PERIODIC_RATE);

  ipv4_address.nxd_ip_version = NX_IP_VERSION_V4;
  ipv4_address.nxd_ip_address.v4 = IP_ADDRESS(235, 2, 3, 5);
  // ipv4_address.nxd_ip_address.v4 = IP_ADDRESS(192, 168, 4, 4);

  /* Create a UDP socket.  */
  status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

  /* Check status.  */
  if (status)
  {
    error_counter++;
    printf("thread_0_entry(): nx_udp_socket_create error, error counter = %lu\n", error_counter);
    return;
  }

  /* Bind the UDP socket to the IP port.  */
  status =  nx_udp_socket_bind(&socket_0, 45678, TX_WAIT_FOREVER);

  /* Check status.  */
  if (status)
  {
    error_counter++;
    printf("thread_0_entry(): nx_udp_socket_bind error, error counter = %lu\n", error_counter);
    return;
  }

  /* Disable checksum logic for this socket.  */
  nx_udp_socket_checksum_disable(&socket_0);

  /* Setup the ARP entry for the UDP send.  */
  //    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0, 0);

  unsigned char count = 0;
  char strBuffer[64];
  while (1)
  {
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
      break;
    }
    sprintf(strBuffer, "ThreadX Sends Packet %#04x\n", count);
    uint8_t strLen = (uint8_t)strlen(strBuffer) + 1;
    // Write buffer into the packet payload!
    nx_packet_data_append(my_packet, strBuffer, strLen, &pool_0, TX_WAIT_FOREVER);

    // Send the UDP packet.  
    status =  nxd_udp_socket_send(&socket_0, my_packet, &ipv4_address, 56789);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
      error_counter++;
      printf("thread_0_entry(): nxd_udp_socket_send error, error counter = %lu\n", error_counter);
      break;
    }

    printf("thread_0_entry(): Sent Packet\n");

    tx_thread_sleep(512);
    ++count;
  }
  printf("Leaving thread_0_entry(), error counter = %lu\n", error_counter);
}


void    thread_1_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *my_packet;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("In thread_1_entry()\n");

    tx_thread_sleep(4 * NX_IP_PERIODIC_RATE); //expacting that socket to be ready, it's higher priority anyway - hack

    while (1)
    {
        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_0, &my_packet, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

        printf("thread_1_entry(): Received Packet\n");
        printf("thread_1_entry(): Content: %s\n", (char*)(my_packet->nx_packet_prepend_ptr));

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

    }
    printf("Leaving thread_1_entry()\n");
}

void    thread_2_entry(ULONG thread_input) {
    NX_PARAMETER_NOT_USED(thread_input);

    printf("In thread_2_entry()\n");

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    axb_pcap_loop("veNet1");

    printf("Leaving thread_2_entry()\n");
}

