//#include "main.h"
#include "arp.h"

#define ARRAYBUF 128

/*
 *  look into the arp table to match the addr
 *  pass address (IP address) and interface fromt possibly routing table. it will return the ether addresss
 */
int arp_lookup(struct in_addr address ,uint8_t *ether_send , const char* ifname){
	FILE *arp_fd ;
	int num , type , flags;
	char ip[ARRAYBUF] = {0,} , line[ARRAYBUF]={0,};
	char hwa[ARRAYBUF]={0}, mask[ARRAYBUF]={0},dev[ARRAYBUF]={0};
	struct ether_addr *ether_a;
	struct in_addr ip_n;
	int i=0;

	/* ipaddr contains the ip address in the . format */
	//ipaddr = inet_ntoa( address );

	arp_fd = fopen("arp.txt" , "r");
	if(arp_fd == NULL){
		printf("ERROR: while opening the arp fd\n");
		exit(1);
	}
	/* will get the first line , ignore that*/
	fgets( line, sizeof(line), arp_fd );
	/*IP address       HW type     Flags       HW address            Mask     Device*/
	while(fgets(line , sizeof(line), arp_fd)){
		num = sscanf( line, "%s 0x%x 0x%x %s %s %s\n", ip, &type, &flags, hwa, mask, dev );

		inet_aton(ip , &ip_n);

		if(num < 4){
			continue;   /* not sure why?? */
		}
		/* if interface not mached  , look for the second line */
		if( strcmp(dev , ifname) == 0){
			ether_a = ether_aton(hwa);
		    for(i=0;i<ETHER_ADDR_LEN;i++) // saving in the frame(source MAC address)
		    	ether_send[i] = ether_a->ether_addr_octet[i];
			//memcpy(ether_send , ether_a->octet , ETHER_ADDR_LEN);
		//	fprintf(stdout , "%s -> %s\n" , ip . hwa);
			fclose(arp_fd);
			return 1;

		}
		/* we dont want broadcast MAC address */
		if( strcmp( hwa, "00:00:00:00:00:00" ) == 0 ||
				strcmp( hwa, "FF:FF:FF:FF:FF:FF" ) == 0 ||
				strcmp( hwa, "ff:ff:ff:ff:ff:ff" ) == 0 ){
			continue;
		}
		/* gotcha */
/*		if(ip_n.s_addr == address.s_addr ){
			ether_a = ether_aton(hwa);
		    for(i=0;i<ETHER_ADDR_LEN;i++) // saving in the frame(source MAC address)
		    	ether_send[i] = ether_a->ether_addr_octet[i];
			//memcpy(ether_send , ether_a->octet , ETHER_ADDR_LEN);
		//	fprintf(stdout , "%s -> %s\n" , ip . hwa);
			fclose(arp_fd);
			return 1;
		}*/
	}
	fclose(arp_fd);
	return -1;

}

