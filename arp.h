
#ifndef __ARPH__
#define __ARPH__

#include <stdio.h>
#include <stdlib.h>
#include<pcap/pcap.h>
#include<sys/socket.h>
#include<net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include<arpa/inet.h> // for inet_ntoa()
//#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

/* for using getifaddrs */
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <stdint.h>
/* for myif structure */

#include <string.h>


int arp_lookup(struct in_addr address ,uint8_t *ether_send , const char* ifname);
#endif

