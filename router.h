
#ifndef __ROUTERH__
#define __ROUTERH__

#include <stdio.h>
#include <stdlib.h>
#include<pcap/pcap.h>
#include<sys/socket.h>
#include<net/ethernet.h>

#include <netinet/in.h>

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

#define ARRAYBUF 128


struct myrt_table {
	struct in_addr d_ipaddr;
	struct in_addr gw_addr;
	struct in_addr mask;
	char intfc[ARRAYBUF];
	struct myrt_table *next;
};
//extern struct rt_table *rt_head;


struct myrt_table* lookup_route(struct in_addr dest_ip );
int delfrom_route(uint32_t dest_ip , char *filename);
int addto_route(char *filename);

#endif
