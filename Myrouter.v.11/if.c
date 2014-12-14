

#include "if.h"
extern myif *if_head;
#define ETHER_ADDR_LEN_MY 6



myif* get_interface_by_IP(u_char *addr)
{
	int i=0 ;
    myif* if_walker = if_head ;

	while(if_walker != NULL){
		for( i = 0 ; i< ETHER_ADDR_LEN_MY ; i++){
			if(if_walker->addr[i] != (uint8_t)addr[i])
				break;
		}
		if(i == ETHER_ADDR_LEN_MY){
			return if_walker;
		} else {
			if_walker = if_walker->next;
		}
	}
	return NULL;

}


myif* get_interface(const char* name)
{
    myif* if_walker = if_head ;

    while(if_walker)
    {
       if(!strncmp(if_walker->name,name,sr_IFACE_NAMELEN))
        {
    	   return if_walker;
        }
        if_walker = if_walker->next;
    }

    return 0;
}

myif* get_interface_by_handle(pcap_t *handle){
	myif *if_walker = if_head;
    while(if_walker)
    {
       if( handle == if_walker->hand_in || handle == if_walker->hand_out)
        {
    	   return if_walker;
        }
        if_walker = if_walker->next;
    }

    return 0;

}


myif* get_interface_by_index(int index)
{
    myif* if_walker = if_head ;
    /* you can put bound as well */

    while(index)
    {
       if_walker = if_walker->next;
       index--;
    }

    return if_walker;
}



void add_interface(const char* name)
{
    myif* if_walker = if_head;

    /* -- empty list special case -- */
    if(if_walker == NULL)
    {
        if_walker = (myif*)malloc(sizeof(myif));
        if_walker->next = NULL;
        strncpy(if_walker->name,name,sr_IFACE_NAMELEN);
        if_head = if_walker;
        return;
    }

    /* -- find the end of the list -- */
    while(if_walker->next != NULL)
    {
    	if_walker = if_walker->next;
    }

    if_walker->next = (myif*)malloc(sizeof(myif));
    if_walker = if_walker->next;
    strncpy(if_walker->name,name,sr_IFACE_NAMELEN);
    if_walker->next = NULL;
}

void set_ether_addr( uint8_t *my_mac_addr)
{
    myif* if_walker = 0;
    int i=0;

    if_walker = if_head;
    while(if_walker->next)
    {
    	if_walker = if_walker->next;
    }

    /* -- copy address -- */
    for(i=0;i<ETHER_ADDR_LEN_MY;i++) // saving in the frame (Destination MAC address
    	if_walker->addr[i] = my_mac_addr[i];


    //memcpy(if_walker->addr,addr,ETHER_ADDR_LEN);
}


void set_ether_ip(struct in_addr ip_nbo)
{
    myif* if_walker = if_head;

    while(if_walker->next)
    {
    	if_walker = if_walker->next;
    }

    /* -- copy address -- */
    if_walker->ip = ip_nbo;

}

void set_handler(const char* name){
	myif *if_handle;
	char errbuf[100] ;
	pcap_t *handle_in , *handle_out;
	if(name == NULL){
		printf("Please check my device name is null\n");
	}
	if_handle = get_interface(name);
	if(if_handle == NULL){
		printf("Please check set_handler:if.c\n");
	}
	handle_in = pcap_open_live(if_handle->name , 65536 , 1 , 0 , errbuf);
	if(handle_in == NULL){
		printf("Please check handle_in \n");
		exit(1);
	}
	handle_out = pcap_open_live(if_handle->name , 65536 , 1 , 0 , errbuf);
	if(handle_out == NULL){
		printf("Please check handle_out\n");
		exit(1);
	}
	if_handle->hand_in = handle_in;
	if_handle->hand_out = handle_out;

}



