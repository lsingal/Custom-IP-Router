#include "router.h"
//#include <stdio.h>

#define IPSIZE 4
struct myrt_table *rt_head = NULL;

/* we will pass the ip address as input and return the myrt_table struct from the list */
struct myrt_table* lookup_route(struct in_addr dest_ip ){
	struct myrt_table *best = 0 , *temp = rt_head ;

	if(temp == NULL){
		printf("No entries in the router!!");
		return NULL;
	}
	while( temp != 0 ) {
		if( (dest_ip.s_addr & (temp->mask).s_addr ) == ((temp->d_ipaddr).s_addr & (temp->mask).s_addr)){
			if(best == 0){
				best = temp;
			} else if( best->mask.s_addr < temp->mask.s_addr ) {
				best = temp;
			}
		}
		temp = temp->next;
	}
	return best;
}

/* will implement later on */
/* here we will pass the destip and filename and delete the matching entry rom the routing table and update the nodes accordingly*/
int delfrom_route(uint32_t dest_ip , char *filename){
   return 1;
}

int addto_route(char *filename)
{
	FILE *rt_fd ;
	int  metric, ref, use ,num;
	char dest_addr[ARRAYBUF]={0,}, gateway[ARRAYBUF]={0,},
    subnet[ARRAYBUF]={0,},flags[10], line[ARRAYBUF]={0,} , dev[ARRAYBUF]={0};
	struct in_addr dest_addr_n , geteway_n , subnet_n ;
	struct myrt_table *rt_walker;
    
	printf("Routing table Initialized\n");
	/* ipaddr contains the ip address in the . format */
	//ipaddr = inet_ntoa( *( struct in_addr *)&dest_ip );
	rt_fd = fopen(filename , "r");
	if(!rt_fd  ){
		printf("ERROR: while opening the arp fd\n");
		exit(1);
	}
	/* will get the first line , ignore that*/
	fgets( line, sizeof(line), rt_fd );
	/*IP address       Dest IP     GW IP      Mask     Device*/
	while(fgets(line , sizeof(line), rt_fd)){
		num = sscanf( line, "%s %s %s %s %d %d %d %s \n", dest_addr, gateway, subnet , flags , &metric, &ref,&use, dev );


        if(inet_aton(dest_addr , &dest_addr_n) == 0)
        {
            fprintf(stderr,"Error loading routing table, cannot convert\n");
            return -1;
        }
        if(inet_aton(gateway , &geteway_n) == 0)
        {
            fprintf(stderr,"Error loading routing table, cannot convert\n");
            return -1;
        }
        if(inet_aton(subnet , &subnet_n) == 0)
        {
            fprintf(stderr,"Error loading routing table, cannot convert\n");
            return -1;
        }

        rt_walker = rt_head;
	printf("Routing table UPDATED\n");
		if(rt_head == NULL){
		   rt_walker = (struct myrt_table*)malloc(sizeof(struct myrt_table));
		   rt_walker->next = NULL;
		   rt_walker->d_ipaddr = dest_addr_n;
		   rt_walker->gw_addr = geteway_n;
		   rt_walker->mask = subnet_n;
		   strncpy(rt_walker->intfc , dev , ARRAYBUF);
		   rt_head = rt_walker;
		   continue;
		}

		while(rt_walker->next){
			rt_walker = rt_walker->next;
		}

	    rt_walker->next = (struct myrt_table*)malloc(sizeof(struct myrt_table));
	    rt_walker = rt_walker->next;
		rt_walker->d_ipaddr = dest_addr_n;
		rt_walker->gw_addr = geteway_n;
		rt_walker->mask = subnet_n;
		strncpy(rt_walker->intfc , dev , ARRAYBUF);
	    rt_walker->next = NULL;


	}
	fclose(rt_fd);
	return 0;
}

