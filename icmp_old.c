#include "icmp.h"


/* when TTL = 0*/
void icmp_process(char *buffer , struct ip  *iph , struct ether_header *eth, int hdrlen , int type){
	char new_packet[ICMP_REPLY_PACKET_SIZE];
	struct myrt_table *r_str;
	myif *myinterface;
	char data[ICMP_DATALEN];

	/*manipulate ether */
	swap_ethernet_addr(eth);
	/* copy the modified buffer into the packet */
	memcpy(new_packet , eth , ETHERNET_HEADER_LEN);
	/*copy IP+8 data */
	memcpy(data, iph ,ICMP_DATALEN );
	/* ip manipulation*/
	/* src addr  is my addr , dest is the buffer->s_addr */
	myinterface = get_interface_by_IP(eth->ether_shost);

	/* source IP = myinterface->ip */
	iph->ip_dst = iph->ip_src;
	iph->ip_src = myinterface->ip;
	iph->ip_ttl = 56;
	iph->ip_p = ICMP_PROTOCOL;

    iph->ip_sum = 0;
//    iph->ip_sum = htons(doCheckSum(iph , 20));

    iph->ip_sum = htons(ip_checksum(iph));
    iph->ip_hl =  ICMP_REPLY_PACKET_SIZE - ETHERNET_HEADER_LEN;

    memcpy(new_packet , iph , IP_HEADER_LENGTH_MY);

    fill_interface_struct(new_packet ,  data , type);

    send_me(myinterface->name , new_packet , ICMP_REPLY_PACKET_SIZE);

}

void fill_interface_struct(char *newpacket , char *data , int type){
	myicmp *icmp_packet;
	icmp_packet = (myicmp*)malloc(sizeof(myicmp));
	int offset;

	memset(icmp_packet , 0 , sizeof(myicmp));

	offset = IP_HEADER_LENGTH_MY + ETHERNET_HEADER_LEN;

	if(type == ICMP_DEST_UNREACH){
		/* when routing table */
		icmp_packet->icmp_code = 0;
		icmp_packet->icmp_type = 3;
	} else if(type == ICMP_TTL_ZERO){
		icmp_packet->icmp_code = 0;
		icmp_packet->icmp_type = 11;
	} else if(type == ICMP_TRACEROUTE_TOME){
		icmp_packet->icmp_code = 3;
		icmp_packet->icmp_type = 3;
	}

	icmp_packet->icmp_unused = 0;
	memcpy(icmp_packet->icmpdata , data , ICMP_DATALEN );
	icmp_packet->icmp_cksum = htons(checksum_icmp((char*)icmp_packet , ICMP_HEADER_LEN + ICMP_DATALEN));

	memcpy(newpacket , (char*)icmp_packet , ICMP_HEADER_LEN + ICMP_DATALEN);

}
void swap_ethernet_addr(struct ether_header *eth  ){
    u_char temp_eth[ETHER_ADDR_LEN_MY];

    /*get the src and dest mac addr from the buffer */
    strncpy(temp_eth , eth->ether_shost , ETHER_ADDR_LEN_MY);
    strncpy(eth->ether_shost , eth->ether_dhost , ETHER_ADDR_LEN_MY);
    strncpy(eth->ether_dhost , temp_eth , ETHER_ADDR_LEN_MY);

}

void icmp_echo_req(){



}

void swap_ip_addr(struct ip *iph , struct ether_header *eth_hdr){
	myif *myip;

	myip = get_interface_by_IP(eth_hdr->dhost);

    iph->ip_ttl = 56;

    iph->ip_dst = iph->ip_src;
    iph->ip_src = myip->ip;

    iph->ip_sum = 0;
//    iph->ip_sum = htons(doCheckSum(iph , 20));

    iph->ip_sum = htons(ip_checksum(iph));

}

void modify_icmp(struct icmphdr *icmp_header ,  int t, int c){

     icmp_header->type = t;
     icmp_header->code = c;

     icmp_header->checksum = 0;
     //calculate offset to put in the buffer
     /*Calculate checksum of your packet */
     icmp_header->checksum = hton(checksum_icmp((unsigned char *)icmp_header, sizeof(icmp_header)));

}
unsigned short checksum_icmp(unsigned short *buffer, int length)
{
    unsigned long sum;
    //char *buffer =packet+14+20;
    // initialize sum to zero and loop until length (in words) is 0

    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words
        sum += *buffer++;   // add 1 word of buffer to sum and proceed to the next

    // we may have an extra byte
    if (length==1)
        sum += (char)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16
    sum += (sum >> 16);          // add carry
    return ~sum;
}

