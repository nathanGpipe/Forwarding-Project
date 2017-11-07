#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN     4
#define ARP_FRAME_TYPE  0x0806
#define ETHER_HW_TYPE   1
#define IP_PROTO_TYPE   0x0800
#define OP_ARP_REQUEST  1
#define OP_ARP_REPLY 	2


struct arpheader {
    unsigned short int htype;  /* Hardware Type           */
    unsigned short int ptype;  /* Protocol Type           */
    unsigned char hlen;        /* Hardware Address Length */
    unsigned char plen;        /* Protocol Address Length */
    unsigned short int oper;   /* Op code 	          */
    unsigned char sha[6];      /* Sender hardware address */
    unsigned char spa[4];      /* Sender IP address       */
    unsigned char tha[6];      /* Target hardware address */
    unsigned char tpa[4];      /* Target IP address       */
};

struct ipheader {
	unsigned char ihl_ver;
	unsigned char dif_services;//short?
	unsigned short len;
	unsigned short id;
	unsigned short flg_offst;
  	unsigned char ttl;
  	unsigned char protocol;
  	unsigned short checksum;
  	unsigned char src_addr[4];
  	unsigned char dst_addr[4];
};

struct icmpheader {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
};

struct table_entry {
	char prefix[19];
    char nexthop[16];
    char interface[8];
};

struct ip_addr{
  char inf_name[8];
  int ip;
};

struct mac_addr{
  char inf_name[8];
  int sock_id;
  struct sockaddr_ll* socket;
};

struct inter_list{
	char* name;
	unsigned char* ip;
	unsigned char mac[6];
	int packet_socket;
	struct inter_list* next;
};

char* filename;

unsigned char checksum (unsigned char *data, size_t size) {
    unsigned char check = 0;
    while (size-- != 0) {
        check += *(data++);
	}
	//check ^ 0xFFFF //flips bits
    return check;
}

//thread code
void* interface_code(void* intr) {

	printf("started thread\n");
	struct inter_list* tmp = (struct inter_list*)intr;

	printf("Ready to recieve on %s now\n", tmp->name);

	while(1) {
		char buf[1500];
		
		struct ether_header eh;
		struct ipheader iph;
		struct arpheader ah;
		struct icmpheader ich;

		struct arpheader responseAh;
		struct ether_header responseEh;
		struct ipheader responseIph;
		struct icmpheader responseIch;

		struct sockaddr_ll recvaddr;
		int recvaddrlen=sizeof(struct sockaddr_ll);
		
		int n = recvfrom(tmp->packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
		if(n==-1){printf("%s: ", tmp->name); perror("Why? ");}
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;
		printf("%s Got a %d byte packet\n", tmp->name, n);
		// Copy ethernet header data from buffer
		memcpy(&eh, &buf, 14);
		eh.ether_type = ntohs(eh.ether_type);

		//Building the ethernet header response
		memcpy(&responseEh.ether_dhost, &eh.ether_shost, 6);
		memcpy(&responseEh.ether_shost, &tmp->mac, 6);
		responseEh.ether_type = htons(eh.ether_type);

		memcpy(&buf, &responseEh, 14);

		if (eh.ether_type == ETHERTYPE_ARP) {

			int t_addr, s_addr;
			//Copy ARP data
			memcpy(&ah, &buf[14], 28);
			//printf("%i", ntohs(ah.oper));
			
			//if(ah.tpa 

			printf("Got ARP request \n");
			// Copy ARP source and target addresses
			//memcpy(&s_addr, &ah.spa, 4);
			//memcpy(&t_addr, &ah.tpa, 4);

			//Construct and send response
			//printf("Starting to copy values to response.\n");
			responseAh.htype = htons(ETHER_HW_TYPE);
			responseAh.ptype = htons(IP_PROTO_TYPE);
			responseAh.hlen = ETH_HW_ADDR_LEN;
			responseAh.plen = IP_ADDR_LEN;
			responseAh.oper = htons(OP_ARP_REPLY);

			//printf("Switching source and destination.\n");
			memcpy(&responseAh.sha, &tmp->mac, 6);
			memcpy(&responseAh.spa, &ah.tpa, 4);
			memcpy(&responseAh.tha, &ah.sha, 6);
			memcpy(&responseAh.tpa, &ah.spa, 4);

			//copy to buffer
			//printf("copying to buffer\n");
			memcpy(&buf[14], &responseAh, 28);

			//printf("sending plz\n");
			printf("ARP, %i\n",send(tmp->packet_socket, buf, n, 0));

		}
		else if (eh.ether_type == ETHERTYPE_IP) {
			//if we are the destination

			int t_ip;
			unsigned char checksum_data[20];
			memcpy(&iph, &buf[14], 20);
			//memcpy(&t_ip, &iph.dst_addr, 4);


			memcpy(&responseIph.ihl_ver, &iph.ihl_ver, 8);
			responseIph.dif_services = iph.dif_services;
			responseIph.len = htons(iph.len);
			responseIph.id = htons(iph.id);
			responseIph.flg_offst = htons(iph.flg_offst);
			responseIph.ttl = iph.ttl;//change later
			responseIph.protocol = iph.protocol;
			responseIph.checksum = 0;//byte 10
			memcpy(&responseIph.src_addr, &iph.dst_addr, 4);
			memcpy(&responseIph.dst_addr, &iph.src_addr, 4);

			memcpy(&checksum_data, &responseIph, 20);
			responseIph.checksum = htons(checksum(checksum_data, 20));

			//else look up ip in the routing table
				//arp across that interface for the mac
				//send across that interface

			if(iph.protocol == 1) { //icmp packet
				memcpy(&ich, &buf[34], 4);
				unsigned char checksum_data[2];

				responseIch.type = 0;
				responseIch.code = ich.code;
				memcpy(&checksum_data, &responseIch, 2);
				responseIch.checksum = htons(checksum(checksum_data, 2));

				//copy to buffer
				//ip
				memcpy(&buf[14], &responseIph, 20);
				//icmp
				memcpy(&buf[34], &responseIch, 4);

				send(tmp->packet_socket, buf, n, 0);
			}
        }
    }
	return NULL;
}

char* next_hop() {
	//read routing table
	FILE* fp = fopen(filename, "r");
	struct table_entry ip_table[6];
	char line_string[50];
	char* line = NULL;
	char* rTable = "";
	size_t len = 0;
	size_t read;
	int i = 0;
	while((read = getline(&line, &len, fp)) != -1) {
		//strcpy(line_string, line);
        line_string[read] = '\0';
        strcpy(ip_table[i].prefix, strtok(line, " "));
        strcpy(ip_table[i].nexthop, strtok(NULL, " "));
        strcpy(ip_table[i].interface, strtok(NULL, "\n"));
        printf("%s %s %s\n",ip_table[i].prefix, ip_table[i].nexthop, ip_table[i].interface);
		i++;
	}
	
	free(line);
	fclose(fp);

	return NULL;
}

int main(int argc, char** argv){
	
	filename = argv[1];
	
	//get list of interfaces (actually addresses)
	struct ifaddrs *ifaddr, *tmp;
	struct inter_list *list, *list_tmp, *last;
	
	if(getifaddrs(&ifaddr)==-1){
		perror("getifaddrs");
		return 1;
	}
	
	list = (struct inter_list*)malloc(sizeof(struct inter_list));
	list_tmp = list;

	//have the list, loop over the list
	for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
		printf("hi, %s %i\nAF_PACKET %i, AF_INET %i\n", tmp->ifa_name, tmp->ifa_addr->sa_family, AF_PACKET, AF_INET);
		int packet_socket;

		if(tmp->ifa_addr->sa_family==AF_PACKET) {
			printf("af_pack\n");
			if(strncmp(&(tmp->ifa_name[0]),"lo",2)) {
			//if its not loopback
				//get name
				printf("Interface: %s\n",tmp->ifa_name);
				list_tmp->name = tmp->ifa_name;
				
				//get mac
		  		struct sockaddr_ll* phy_if = (struct sockaddr_ll*)tmp->ifa_addr;
				printf("MAC: ");
				for(int i = 0; i < 6; i++) {
					list_tmp->mac[i] = phy_if->sll_addr[i];
					printf("%i:", list_tmp->mac[i]);
				}
				printf("\n");
				
				//make a socket
				printf("Creating Socket on interface %s\n",tmp->ifa_name);
				packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if(packet_socket<0){
			  		perror("socket");
 			 		return 2;
				}
				if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1) {
					perror("bind");
				}
				
				list_tmp->packet_socket = packet_socket;
				
				//set next
				printf("interfacelist\n");
				struct inter_list *lt = (struct inter_list*)malloc(sizeof(struct inter_list));
				printf("1\n");
				list_tmp->next = lt;
				printf("2\n");
				last = list_tmp;
				list_tmp = list_tmp->next;
				printf("3\n");
				list_tmp->next = NULL;
			}
		}

		if(tmp->ifa_addr->sa_family==AF_INET) {
			printf("af_inet\n");
			struct inter_list* lt;
			for(lt = list; lt!=NULL; lt=lt->next) {
				printf("looping\n");
				if(lt->name==tmp->ifa_name) {
					printf("Interface: %s\n",tmp->ifa_name);
					lt->ip = inet_ntoa(((struct sockaddr_in*)tmp->ifa_addr)->sin_addr);
				}
			}	
		}
		
	}
	
	free(list_tmp);
	last->next = NULL;
	list_tmp = last;
	
	//build threads
	pthread_t inter;
	for(list_tmp = list; list_tmp!=NULL; list_tmp=list_tmp->next) {
		printf("thread\n");
		if(pthread_create(&inter, NULL, interface_code, (void*)list_tmp)) {
			printf("error creating thread\n");
		}
	}

	pthread_join(inter, NULL);

	freeifaddrs(ifaddr);

    return 0;

}

