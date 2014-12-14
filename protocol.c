//#include "router.h"

#include "protocol.h"

char *update_packet(char *buffer , int hdrlen)
{
    struct ether_header *eth = (struct ether_header *)buffer;
    struct ip *iph = (  struct ip *)(buffer + ETHERNET_HEADER_LEN);
    myif *src_eth ;
    uint8_t dest_eth[ETHER_ADDR_LEN_MY];
    struct myrt_table *r_str;
    int i=0;
    char *some_addr;
    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + IP_HEADER_LINE  + sizeof(struct ether_header));

   // uint8_t *ether_dest , *ether_source;

    if(packet_to_me(iph , eth)){
       	/* check if its ICMP protocol */
    	if( iph->ip_p == 1/*ICMP*/ ){
    		myif *myinterface;
    		myinterface = get_interface_by_IP(eth->ether_shost);
    		if(myinterface == NULL){
    			printf("We got the NULL interface: protocol.c");
    			return NULL;
    		}
    		modify_icmp(icmp_header , 0 , 0);
    		swap_ip_addr(iph ,eth);
    		swap_ethernet_addr(eth);
    		send_me(myinterface->name , buffer , hdrlen);
    		return buffer;
    	}else {
    		/* check if TTL == 1 */
    		if(iph->ip_ttl == 1){
    			char *err = NULL;
    			/* trace route ,ICMP_TRACEROUTE_TOME*/
    			err = icmp_process(buffer , iph , eth , 3/*ICMP_TRACEROUTE_TOME*/);
    			if(err == NULL){
    				printf("error when TTL is 1 :protocol.c\n");
    				return NULL;
    			}
    		} else {
    			/*not possible case */
    		}
    	}
    } else {
    	/* forward to next hop */
        if(iph->ip_ttl <= 1){
        	char *err = NULL;
        	icmp_process(buffer , iph , eth  , 1/*ICMP_TTL_ZERO*/);
   			if(err == NULL){
    				printf("error when TTL is 1 :protocol.c\n");
    				return NULL;
   			}
        	return (char*)1;
        }
        iph->ip_ttl--;
        iph->ip_sum = 0;
    //    iph->ip_sum = htons(doCheckSum(iph , 20));

        iph->ip_sum = htons(ip_checksum(iph));
        some_addr = inet_ntoa(iph->ip_dst);
    	r_str = lookup_route(iph->ip_dst);

    	if(r_str == NULL){
        	icmp_process(buffer , iph , eth  , 2/*ICMP_DEST_UNREACHED*/);
    		return NULL;
    	}

        src_eth = lookup_src_mac_addr( r_str ); // will return mac address of the source
        if((lookup_dest_mac_addr(iph->ip_dst , r_str , dest_eth)) ==0){
        	printf("NO ARP while lookup address\n");
        	/* send ICMP that we canot find */
        	return NULL;
        }

        //ether_source = parse_ether_address(src_eth->addr); // parse and convert into int

        for(i=0;i<ETHER_ADDR_LEN_MY;i++) // saving in the frame(source MAC address)
    		eth->ether_shost[i] = src_eth->addr[i];

       // ether_dest = parse_ether_address(dest_eth);

        for(i=0;i<ETHER_ADDR_LEN_MY;i++) // saving in the frame (Destination MAC address
            eth->ether_dhost[i] = dest_eth[i];

        send_me(r_str->intfc , buffer , hdrlen);
    	return (char*)1;
    }
    return NULL;
}

int packet_to_me(struct ip *iph , struct ether_header *eth_hdr ){
	myif *myip ;

    myip = get_interface_by_IP(eth_hdr->ether_dhost);

    if((iph->ip_dst).s_addr ==  (myip->ip).s_addr){
	printf("This packet is for me!\n");
    	return 1;
    }
    return 0;
}

uint16_t ip_checksum (struct ip *ip_hdr)
{   int *ipsrc_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_src));
    int *ipdst_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_dst));
    
    int sum = (((unsigned int)ip_hdr->ip_v<<12 | (unsigned int)ip_hdr->ip_hl<<8 | (ip_hdr->ip_tos)) +
               (ntohs(ip_hdr->ip_len))+
               (ntohs(ip_hdr->ip_id))+
               (ntohs(ip_hdr->ip_off))+
               ((ip_hdr->ip_ttl)<<8 | (ip_hdr->ip_p))+
               (ipsrc_parse[0]<<8 | ipsrc_parse[1])+
               (ipsrc_parse[2]<<8 | ipsrc_parse[3])+
               (ipdst_parse[0]<<8 | ipdst_parse[1])+
               (ipdst_parse[2]<<8 | ipdst_parse[3]));
    
    int chk_sum = ((sum & 0x0000ffff) + ((sum & 0xffff0000)>>16));
	printf("CheckSum done\n");
    
    return (uint16_t)(~chk_sum);
}

int send_me(char *infc, const char* buf , int hdrlen)
{
	//pcap_t *eth_handle;
	myif *out_handle;
	int packets_injected ;
    struct ether_header *eth = (struct ether_header *)buf;
    struct ip *iph = (  struct ip *)(buf + ETHERNET_HEADER_LEN);

    printf("source HW addr: %x:%x:%x:%x:%x:%x,",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
    printf("Dest HW addr: %x:%x:%x:%x:%x:%x,",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

    printf("Source IP address: %s ",inet_ntoa(iph->ip_src) );
    printf("Dest IP address: %s ",inet_ntoa(iph->ip_dst) );
    printf("IP checksum     : %x\n",(uint16_t)ntohs(iph->ip_sum));

	//eth_handle = pcap_open_live(r_str->intfc,65535,0, 0, errbuf);
    out_handle = get_interface(infc);

	packets_injected = pcap_inject(out_handle->hand_out ,(const char *) buf, hdrlen);
    printf("\ninjected: %d\n",packets_injected);
    if( packets_injected == -1 ) {
        printf("error: %s\n",pcap_geterr(out_handle->hand_out));
        pcap_perror(out_handle->hand_out,0);
        /* donot close it */
        //pcap_close(eth_handle);
        //exit(1);
	return 1;
    }
   // pcap_close(eth_handle);
    return 1;
}
                                       

int* parse_ip_address(char *ipaddr)
{   //printf("parse ip address\n");
    int i = -1, num = 0, p = 1,j=0;
    int *ipaddr_parse = malloc(sizeof(int)*4);
    char ch;
    do
    {
        i++;
        ch = ipaddr[i];
        if(ch == '.' || ch == '\0')
        {
            ipaddr_parse[j] = num;
            p = 1;
            num = 0;
            j++;
        }
        else
        {
            num = num*p + (ch-48);
            if (p == 1) p = 10;
        }
    } while(ipaddr[i]!='\0');

//printf("\n%d %d %d %d\n",ipaddr_parse[0], ipaddr_parse[1], ipaddr_parse[2], ipaddr_parse[3]);
return ipaddr_parse;
}

                                       
/* MAC for lookup destination */
int lookup_dest_mac_addr(struct in_addr dest_ip,struct myrt_table* r_str , uint8_t* dest_eth)
{
   // char addr[ETHER_ADDR_LEN]; /* network format */
    if(arp_lookup( dest_ip, dest_eth ,r_str->intfc)!=-1)
    {
	printf("Success: ARP table\nGot the Destination Address\n");
        return 1;
    }
    return 0;
}

/* MAC for lookup source */
myif * lookup_src_mac_addr(struct myrt_table *r_str)
{
//We will get the pointer to struct interface for ethernet name
    myif *int_eth = get_interface(r_str->intfc);
	printf("Got the source address\n");
    return int_eth;
}

uint8_t *parse_ether_address(char *ether_addr_str)
{
    int i =-1,c,j=0;
    char ch;
    uint8_t num=0, *ether_addr = malloc(sizeof(int)*6);
    do
    {
    i++;
    ch = ether_addr_str[i];// mac of eth1
        if(ch == ':' || ch == '\0')
        {
            ether_addr[j] = num;
            printf(" num in if is %x:\n",num);
            num = 0;
            j++;
        }
        else
        {
            c = (ch>57)? ch-87 : ch-48;
            num = num*16 + c;
            printf(" num in else is %x:\n",num);
        }
    } while(ether_addr_str[i] != '\0');

    printf("MAC- ");
    for(i=0;i<6;i++)
    printf("%x:",ether_addr[i]);
    printf("\n");

    return ether_addr;
}





