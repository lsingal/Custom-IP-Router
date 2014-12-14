#ifndef __MAINH__
#define __MAINH__

#include <stdio.h>
#include <stdlib.h>
#include<pcap/pcap.h>
#include<sys/socket.h>
#include<net/ethernet.h>
#include <pthread.h>

#include <netinet/in.h>

#include<arpa/inet.h> // for inet_ntoa()
//#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header

#include <netinet/ether.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

/* for using getifaddrs */
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <stdint.h>
/* for myif structure */

#include <string.h>

#include "if.h"
#include "protocol.h"

 #include <unistd.h>
/* global variables */
extern myif *if_head ;



struct ether_addr *getMyMac(char *device) ;
void process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *buffer);
int checkPacketValidity(char *buffer) ;
void join_threads();
void *handler(void* hand_num);
int create_threads(int n);
struct in_addr getMyIP(char *device);

#endif

