
#ifndef _PROTOCOLH_
#define _PROTOCOLH_

#include "if.h"
#include "router.h"
#include "arp.h"
#include "icmp.h"



#define ETHER_ADDR_LEN_MY 6
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LINE 20


char *update_packet(char *buffer , int hdrlen);
uint16_t ip_checksum (struct ip *ip_hdr);
int* parse_ip_address(char *ipaddr);
int lookup_dest_mac_addr(struct in_addr dest_ip,struct myrt_table* r_str , uint8_t* dest_eth);
myif *lookup_src_mac_addr(struct myrt_table *r_str);
uint16_t doCheckSum (const void *_data, int len);
uint8_t *parse_ether_address(char *ether_addr_str);
int send_me(char *intfc, const char* buf , int hdrlen);
int packet_to_me(struct ip *iph , struct ether_header *eth_hdr );
#endif
