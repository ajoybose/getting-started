#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>

#define AXB_ETHERNET_HEADER_SIZE 14
#define AXB_MTU_SIZE 1500

static char pcap_errbuf[PCAP_ERRBUF_SIZE];

static pcap_t* pcap = NULL;

static unsigned char g_frame[AXB_MTU_SIZE];

extern unsigned char myMAC[6];

extern void _nx_pcap_network_driver_receive(const unsigned char* pucFrame, unsigned short usSize);

static void axb_fixIPChecksum(unsigned char* pIpHdrStart) {
  unsigned short checksum = 0;
  for (uint8_t i = 0; i < 20; i += 2) {
    unsigned short tmp = pIpHdrStart[i];
    tmp = tmp << 8;
    tmp = tmp | pIpHdrStart[i + 1];
    unsigned short diff = 65535 - checksum;
    checksum += tmp;
    if (tmp > diff) {
      checksum += 1;
    }
  }
  checksum = ~checksum;
  checksum = htons(checksum);
  memcpy((void*)&pIpHdrStart[10],(void*)&checksum, 2); // correct checksum
}

int axb_init_pcap(const char* pcInterfaceName) {
  pcap_errbuf[0]='\0';
  pcap=pcap_open_live(pcInterfaceName, AXB_MTU_SIZE, 1, 1000, pcap_errbuf);
  if (pcap_errbuf[0]!='\0') {
    fprintf(stderr,"%s\n",pcap_errbuf);
  }
  if (!pcap) {
    return -1;
  }
  return 0;
}

int axb_pcap_send_packet(unsigned char* pucFrame, unsigned short usSize) {
  if (pcap == NULL) {
    fprintf(stderr, "NULL PCAP Handle\n");
    return -2;
  }
  // Add IP Header Checksum
  axb_fixIPChecksum(pucFrame + AXB_ETHERNET_HEADER_SIZE);
  // Write the Ethernet frame to the interface.
  fprintf(stdout, "calling pcap_inject with buffer size %u\n", usSize);
  if (pcap_inject(pcap, pucFrame, usSize) == -1) {
    fprintf(stderr, "pcap_inject Failed\n");
    pcap_perror(pcap,0);
    pcap_close(pcap);
    pcap = NULL;
    return -3;
  }
  return 0;
}


char* getMACStr(const unsigned char* pucAddress) {
  static char out[18];
  uint8_t countChar = 0;
  for (uint8_t count = 0; count < 6; ++count) {
    sprintf(&out[countChar], "%02x", pucAddress[count]);
    countChar += 2;
    if (count < 5) {
	    sprintf(&out[countChar], ":");
	    ++countChar;
    }
  }
  return  out;
}

bool checkIPChecksum(const u_char *pIpHdrStart) {
  unsigned short checksum = 0;
  for (uint8_t i = 0; i < 20; i += 2) {
    unsigned short tmp = pIpHdrStart[i];
    tmp = tmp << 8;
    tmp = tmp | pIpHdrStart[i + 1];
    unsigned short diff = 65535 - checksum;
    checksum += tmp;
    if (tmp > diff) {
      checksum += 1;
    }
  }
  if (checksum == 0xFFFF) {
    return true;
  }
  else {
    return false;
  }
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  static unsigned char count = 0;
  fprintf(stdout, "%3u\n", count);
  unsigned short framePos = 0;
  fprintf(stdout, "Received Packet:\n");
  fprintf(stdout, "Destination MAC: %s\n", getMACStr(&packet[framePos]));
  framePos += 6;
  fprintf(stdout, "Source MAC: %s\n", getMACStr(&packet[framePos]));
  framePos += 6;
  unsigned short temp;
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "Ethernet Type: %#06x\n", temp);

  if (memcmp(&packet[6], myMAC, 6) == 0) {
    fprintf(stdout, "Skipping My Send Packet\n");
    return;
  }

  _nx_pcap_network_driver_receive(&packet[0], header->caplen); 
  

  if (temp != 0x0800) {
    fprintf(stderr, "NOT IP Packet\n");
    return;
  }
  if (checkIPChecksum(&packet[framePos])) {
    fprintf(stdout, "IP CheckSum OK\n");
  }
  else {
    fprintf(stderr, "IP CheckSun FAILED\n");
  }
  if (packet[framePos] != 0x45) {
    fprintf(stderr, "Unexpected IP HDR first byte %#04x\n", packet[framePos]);
    return;
  }
  framePos += 2;
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "IP Packet Size: %u\n", temp);
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "IP Packet ID: %#06x\n", temp);
  framePos += 3; // skip
  if (packet[framePos] != 0x11) {
    fprintf(stderr, "NOT UDP, Type: %#04x\n", packet[framePos]);
    return;
  }
  framePos += 1;
  framePos += 2; // skip
  struct in_addr tmp_addr;
  tmp_addr.s_addr = (unsigned long) *(unsigned long*)&packet[framePos];
  framePos += 4;
  fprintf(stdout, "Source IP %s\n", inet_ntoa(tmp_addr));
  tmp_addr.s_addr = (unsigned long) *(unsigned long*)&packet[framePos];
  framePos += 4;
  fprintf(stdout, "Destination IP %s\n", inet_ntoa(tmp_addr));
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "Source Port: %#06x\n", temp);
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "Destination Port: %#06x\n", temp);
  temp = ntohs(*(unsigned short*)&packet[framePos]);
  framePos += 2;
  fprintf(stdout, "UDP Packet Size: %#06x\n", temp);
  framePos += 2; // skip
  // fprintf(stdout, "Payload: %s\n", (char*)&packet[framePos]);

  ++count;
}


int axb_pcap_loop(const char* if_name) {
  fprintf(stdout, "axb_pcap_loop(): My MAC Address is %s\n", getMACStr(myMAC)); 
  // Open a PCAP packet capture descriptor for the specified interface.
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0]='\0';
  pcap_t* pcap = pcap_open_live(if_name, AXB_MTU_SIZE, 1, 1000, pcap_errbuf);
  if (pcap_errbuf[0]!='\0') {
    fprintf(stderr,"%s\n",pcap_errbuf);
  }
  if (pcap == NULL) {
    fprintf(stderr, "NULL PCAP Handle\n");
    return -2;
  }

  while (pcap_loop(pcap, 0, my_packet_handler,  NULL) == 0) {
    fprintf(stdout, "looping pcap_loop");
  }
  
  // Close the PCAP descriptor.
  pcap_close(pcap);

  fprintf(stdout, "leaving axb_pcap_loop");

  return 0;
}

