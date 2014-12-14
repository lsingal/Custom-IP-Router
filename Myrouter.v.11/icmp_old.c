#include "icmp.h"


/* when TTL = 0*/
char *icmp_process(char *buffer , struct ip  *iph , struct ether_header *eth, int type){
	char new_packet[ICMP_REPLY_PACKET_SIZE];
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
	if(myinterface == NULL){
		printf("Null interface while ICMP process\n");
		return NULL;
	}

	/* source IP = myinterface->ip */
	iph->ip_dst = iph->ip_src;
	iph->ip_src = myinterface->ip;
	iph->ip_ttl = 56;
	iph->ip_p = ICMP_PROTOCOL;

    iph->ip_sum = 0;
//    iph->ip_sum = htons(doCheckSum(iph , 20));

    iph->ip_sum = htons(ip_checksum(iph));
    iph->ip_hl = 5/* ICMP_REPLY_PACKET_SIZE - ETHERNET_HEADER_LEN*/;
/* some issue here */
    memcpy(new_packet , iph , IP_HEADER_LENGTH_MY);

    fill_interface_struct(new_packet ,  data , type);

    send_me(myinterface->name , new_packet , ICMP_REPLY_PACKET_SIZE);

    return (char*)1;

}

void fill_interface_struct(char *newpacket , char *data , int type){
	myicmp *icmp_packet;
	icmp_packet = (myicmp*)malloc(sizeof(myicmp));
	int offset;
	uint8_t ty ,co;


	memset(icmp_packet , 0 , sizeof(myicmp));

	offset = IP_HEADER_LENGTH_MY + ETHERNET_HEADER_LEN;

	if(type == 2/*ICMP_DEST_UNREACHED*/){
		/* when routing table */
		ty=0;co=3;
		icmp_packet->icmp_code_my = ty;
		icmp_packet->icmp_type_my = co;
	} else if(type == 1/*ICMP_TTL_ZERO*/){
		ty=0;co=11;
		icmp_packet->icmp_code_my = ty;
		icmp_packet->icmp_type_my = co;
	} else if(type == 3/*ICMP_TRACEROUTE_TOME*/){
		ty=3;co=3;
		icmp_packet->icmp_code_my = ty;
		icmp_packet->icmp_type_my = co;
	}

	icmp_packet->icmp_unused_my = (uint32_t)0;
	memcpy(icmp_packet->icmpdata , data , ICMP_DATALEN );
	icmp_packet->icmp_cksum_my = htons(checksum_icmp((unsigned char*)icmp_packet , ICMP_HEADER_LEN + ICMP_DATALEN));

	memcpy(newpacket , (char*)icmp_packet , ICMP_HEADER_LEN + ICMP_DATALEN);

}
void swap_ethernet_addr(struct ether_header *eth  ){
    u_char temp_eth[ETHER_ADDR_LEN_MY];

    /*get the src and dest mac addr from the buffer */
    strncpy((char*)temp_eth , (char*)eth->ether_shost , ETHER_ADDR_LEN_MY);
    strncpy((char*)eth->ether_shost , (char*)eth->ether_dhost , ETHER_ADDR_LEN_MY);
    strncpy((char*)eth->ether_dhost , (char*)temp_eth , ETHER_ADDR_LEN_MY);

}


void swap_ip_addr(struct ip *iph , struct ether_header *eth_hdr){
	myif *myip;

	myip = get_interface_by_IP(eth_hdr->ether_dhost);

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

     /* issue:check this cksum , may be wrong;;;include the data as well*/
     icmp_header->checksum = htons(checksum_icmp((unsigned char *)icmp_header, sizeof(icmp_header)));

}
uint16_t checksum_icmp(unsigned char *buffer, int length)
{
	uint16_t sum;
    //char *buffer =packet+14+20;
    // initialize sum to zero and loop until length (in words) is 0

    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words
        sum += *buffer++;   // add 1 word of buffer to sum and proceed to the next

    // we may have an extra byte
    if (length==1)
        sum += (char)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16
    sum += (sum >> 16);          // add carry
    return (uint16_t)(~sum);
}



