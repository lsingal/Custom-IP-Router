#ifndef __IFH__
#define __IFH__

#include <stdint.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include<pcap/pcap.h>


#define sr_IFACE_NAMELEN 32

/* make the interface structure global*/

typedef struct my_if
{
    char name[sr_IFACE_NAMELEN];
    uint8_t addr[ETHER_ADDR_LEN];
    struct in_addr ip;
    pcap_t *hand_in;
    pcap_t *hand_out;
    struct my_if* next;
}myif;

myif* get_interface(const char* name);
void add_interface( const char* name);
void set_ether_addr( uint8_t *my_mac_addr);
void set_ether_ip(struct in_addr ip_nbo);
myif* get_interface_by_index(int );
myif* get_interface_by_handle(pcap_t *);
void set_handler(const char* name);
myif* get_interface_by_IP(u_char *addr);

#endif
