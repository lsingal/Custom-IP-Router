/*
 ============================================================================
 Name        : MyRouter.c
 Author      : LavishSingal
 Version     :
 Copyright   : I am writing my custom Router
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "main.h"



#define ICMP 1
#define TCP 6
#define UDP 17
#define OSPF 89
#define ETHERTYPE_IP 0x0800


#define ETHER_ADDR_LEN_MY 6
#define ARRAYBUF 128
#define IPV4_HEADER_LEN 20
#define ETHERNET_HEADER_LEN 14
#define FILEPATH "rt.txt"

#define TOTAL_THREADS 3
pthread_t thrd[TOTAL_THREADS];

struct sockaddr_in source,dest;
int total=0,i,j ;
int num_of_threads =0 ;
myif *if_head ;


/* store all the interfaces */

/* array of pointers and store the address of various handler functions */

void *handler(void* hand_num){
	myif *if_handle ;
	if_handle = get_interface_by_index(*((int*)hand_num));

    //Put the device in sniff loop
    /* add pcap_setdirection and pcap_filter */
    if( pcap_setdirection(if_handle->hand_in , PCAP_D_IN) < 0 ){
    	printf("error while pcap_setdirection\n");
    }
    pcap_loop(if_handle->hand_in , -1 , process_packet , hand_num);
    return 0;
}

int create_threads(int n){
	int errno = 0,i=0;
	int *index;

	for(i = 0 ; i< n ;i++){
		index = malloc(sizeof(int));
		if(index == NULL){
			printf("Error while malloc!\n");
			exit(1);
		}
		*index = i;
	    if((errno = pthread_create(&thrd[i], 0,handler, (void*)index ))){
	        fprintf(stderr, "pthread_create[0] %s\n",strerror(errno));
	        pthread_exit(0);
	    }
	}
	return 1;
}

void sniffPacket(){
    pcap_if_t *device , *alldevsp;
    char errbuf[100]  ;
    struct sockaddr_in myaddr;
    int n = 0;
    struct in_addr myaddr_network;
    char *myaddr_human;

     //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }

    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , num_of_threads , device->name , device->description);
        if(device->name != NULL && (strncmp(device->name , "eth" , 3) == 0))
        {
        	myaddr_network = getMyIP(device->name );
        	myaddr_human = inet_ntoa(myaddr_network);

        	if(strncmp(myaddr_human , "10." , 3) != 0){
        		continue;
        	}

        	/* store it in the interface structure */
        	add_interface(device->name);
        	set_ether_ip(myaddr_network);
        	set_ether_addr((getMyMac(device->name))->ether_addr_octet);
        	set_handler(device->name);
        	num_of_threads++;
        }

    }

    n = create_threads(num_of_threads);
    if( n < 0){
    	printf("Thread creation error::::\n");
    	exit(1);
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *buffer){
	struct ip *ip_hdr = (struct ip *)(buffer + ETHERNET_HEADER_LEN);
    unsigned short type = ntohs(*(unsigned short*)(buffer + ETHER_ADDR_LEN_MY + ETHER_ADDR_LEN_MY));
    struct ether_header *eth = (struct ether_header *)buffer;

    char *err = NULL;

	/* check if this packet for us */
	if(!(checkPacketValidity((char*)buffer))){
		/* drop the packet */
//		printf("Packet is not meant for us!!!");
		return ;
	}
	/* send packet only if it is IP packet and not ARP packet */
	if(type == ETHERTYPE_IP){
		switch (ip_hdr->ip_p){
		case TCP:
		case UDP:
		{
			printf("Recived TCP/UDP packet info: \n");
			    printf("source HW addr: %x:%x:%x:%x:%x:%x,",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
			    printf("Dest HW addr: %x:%x:%x:%x:%x:%x,",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

			    printf("Source IP address: %s ",inet_ntoa(ip_hdr->ip_src) );
			    printf("Dest IP address: %s ",inet_ntoa(ip_hdr->ip_dst) );
			    printf("IP checksum     : %x\n",(uint16_t)ntohs(ip_hdr->ip_sum));

			err = update_packet( (char*)buffer , header->len);
			if(err == NULL){
//				printf("Some issue in main.c\n");
				return;
			}
		}
			break;
		case ICMP:
		{
			printf("Recieved ICMP packet\n");
			err = update_packet( (char*)buffer , header->len);
			if(err == NULL){
//				printf("Some issue in main.c\n");
				return;
			}
		}
		case OSPF:
			//update_ospf_packet(buffer , header->len);
			break;
		default:
			//do something for ARP as well ?
			break;
		}
	}
}

struct in_addr getMyIP(char *device){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , device , sizeof(device));
    ioctl(fd, SIOCGIFADDR, &ifr);
    printf("IP address of %s - %s\n" , device , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
    close(fd);
    return ( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr;
}

struct ether_addr *getMyMac(char *device) {
	FILE *dev_fd;
	struct ether_addr *eth_addr;
	char path[ARRAYBUF] = "/sys/class/net/" , line[ARRAYBUF];
	strcat(path , device);
	strcat(path , "/address");
	/* path = /sys/class/net/eth0/address , will give us the address : 00:04:23:ae:d1:4e*/
	dev_fd = fopen(path,"r");
	fgets( line, sizeof(line), dev_fd );
	eth_addr = ether_aton(line);
	return eth_addr;
}

/* returns 0 if this packet is for this router others return -1 */
int checkPacketValidity(char *buffer) {
	struct ether_header *eth_hdr = (struct ether_header *)buffer;
	myif *iface = NULL;
	int i=0 ;

	iface = if_head;

	while(iface != NULL){
		for( i = 0 ; i< ETHER_ADDR_LEN_MY ; i++){
			if(iface->addr[i] != (uint8_t)eth_hdr->ether_dhost[i])
				break;
		}
		if(i == ETHER_ADDR_LEN_MY){
			return 1;			
		} else {
			iface = iface->next;
		}
	}	
	return 0;
}

void join_threads(){
	int i =0 , errno =0;
    for (i=0; i<num_of_threads; i++) {
        if((errno = pthread_join(thrd[i], 0))){
            fprintf(stderr, "pthread_join[i] %s\n",strerror(errno));
            pthread_exit(0);
        }
    }
}

int main(int argc , char *argv[]) {
	if((addto_route(FILEPATH))<0){
	printf("Error while adding routes!!\n");
	}
	sniffPacket();
	join_threads();
	return 0;
}




