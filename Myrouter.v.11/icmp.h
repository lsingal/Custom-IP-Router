#ifndef __ICMPH__
#define __ICMPH__

#include "if.h"
#include "router.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include<net/ethernet.h>

#include "protocol.h"
#include<netinet/ip_icmp.h>
 
#define ICMP_DATALEN 28
#define ICMP_PROTOCOL 1
#define ICMP_HEADER_LEN 8
#define IP_HEADER_LENGTH_MY 20
#define ICMP_TTL_ZERO 1
#define ICMP_DEST_UNREACHED 2 
#define ICMP_TRACEROUTE_TOME 3

#define ICMP_REPLY_PACKET_SIZE 70

typedef struct my_icmp {
	uint8_t  icmp_type_my;	/* type of message, see below */
	uint8_t  icmp_code_my;	/* type sub code */
	uint16_t icmp_cksum_my;	/* ones complement checksum of struct */
	uint32_t icmp_unused_my;
	char icmpdata[ICMP_DATALEN+5];
}myicmp;

void modify_icmp(struct icmphdr *icmp_header , int type, int code);
void swap_ip_addr(struct ip *iph , struct ether_header *eth_hdr);
char *icmp_process(char *buffer , struct ip  *iph , struct ether_header *eth , int type);
void fill_interface_struct(char *newpacket , char *data , int type);
void swap_ethernet_addr(struct ether_header *eth  );
uint16_t checksum_icmp(unsigned char *buffer, int length);


#endif


