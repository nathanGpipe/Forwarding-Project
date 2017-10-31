
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <string.h>

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
	unsigned char ihl_ver[8];
	unsigned short dif_services;
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

struct ip_addr{
  char inf_name[8];
  int ip;
};

struct mac_addr{
  char inf_name[8];
  int sock_id;
  struct sockaddr_ll* socket;
};

unsigned int checksum (unsigned int *data, size_t size) {
    unsigned int check = 0;
    while (size-- != 0) {
        check -= *data++;
	}
    return check;
}

int main(){

	int packet_socket;
	unsigned char mac_addr[6];
	//get list of interfaces (actually addresses)
	struct ifaddrs *ifaddr, *tmp;

	if(getifaddrs(&ifaddr)==-1){
		perror("getifaddrs");
		return 1;
	}
	//have the list, loop over the list
	for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {

		if(tmp->ifa_addr->sa_family==AF_INET) {
			// TODO: Create list of IPs? - not now
		}


		if(tmp->ifa_addr->sa_family==AF_PACKET) {

			struct sockaddr_ll* phy_if = (struct sockaddr_ll*)tmp->ifa_addr;

			for(int i = 0; i < 6; i++) {
				mac_addr[i] = phy_if->sll_addr[i];
			}

			printf("Interface: %s\n",tmp->ifa_name);
			if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)) {
		  		printf("Creating Socket on interface %s\n",tmp->ifa_name);
				packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if(packet_socket<0){
		  			perror("socket");
		  			return 2;
				}
			if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1) {
	  			perror("bind");
			}
		}
	}
	freeifaddrs(ifaddr);
	printf("Ready to recieve now\n");

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

		int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
	if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;
		printf("Got a %d byte packet\n", n);
		// Copy ethernet header data from buffer
		memcpy(&eh, &buf, 14);
		eh.ether_type = ntohs(eh.ether_type);

		//Building the ethernet header response
		memcpy(&responseEh.ether_dhost, &eh.ether_shost, 6);
		memcpy(&responseEh.ether_shost, &eh.ether_dhost, 6);
		responseEh.ether_type = htons(eh.ether_type);

		if (eh.ether_type == ETHERTYPE_ARP) {
			int t_addr, s_addr;
			//Copy ARP data
			memcpy(&ah, &buf[14], 28);
			printf("Got ARP request \n");
			// Copy ARP source and target addresses
			memcpy(&s_addr, ah.spa, 4);
			memcpy(&t_addr, ah.tpa, 4);

			//Construct and send response
			responseAh.htype = htonl(ETHER_HW_TYPE);
			responseAh.ptype = htonl(IP_PROTO_TYPE);
			responseAh.hlen = htons(ETH_HW_ADDR_LEN);
			responseAh.plen = htons(IP_ADDR_LEN);
			responseAh.oper = htonl(OP_ARP_REPLY);

			memcpy(&responseAh.sha, &mac_addr, 6);
			memcpy(&responseAh.spa, &ah.tpa, 4);
			memcpy(&responseAh.tha, &ah.sha, 6);
			memcpy(&responseAh.tpa, &ah.spa, 4);
			

			//copy to buffer
			memcpy(&buf[14], &responseAh, 28);

			send(packet_socket, buf, strlen(buf)+1, 0);

		}
		else if (eh.ether_type == ETHERTYPE_IP) {
			int t_ip;
			unsigned int checksum_data[20];
			memcpy(&iph, &buf[14], 20);
			memcpy(&t_ip, iph.dst_addr, 4);


			memcpy(&responseIph.ihl_ver, &iph.ihl_ver, 8);
			responseIph.dif_services = iph.dif_services;
			responseIph.len = iph.len;
			responseIph.id = iph.id;
			responseIph.flg_offst = iph.flg_offst;
			responseIph.ttl = iph.ttl;//change later
			responseIph.protocol = iph.protocol;
			responseIph.checksum = 0;//byte 10
			memcpy(&responseIph.src_addr, &iph.dst_addr, 4);
			memcpy(&responseIph.dst_addr, &iph.src_addr, 4);

			memcpy(&checksum_data, &responseIph, 20);
			responseIph.checksum = checksum(checksum_data, 20);
			
			
			}


			if(iph.protocol == 1) { //icmp packet
				memcpy(&ich, &buf[24], 4);
				unsigned int checksum_data[2];

				responseIch.type = 0;
				responseIch.code = ich.code;
				memcpy(&checksum_data, &responseIch, 2);
				responseIch.checksum = checksum(checksum_data, 2);
				
				//copy to buffer
				memcpy(&buf[24], &responseIch, 4);

				send(packet_socket, buf, strlen(buf)+1, 0);
				
			}
		}
    }

    return 0;

}

