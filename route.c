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
#define OP_ARP_REQUEST  2

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
  	unsigned char ttl;
  	unsigned char protocol;
  	unsigned short checksum;
  	unsigned char src_addr[4];
  	unsigned char dst_addr[4];
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

int main(){

  int packet_socket;
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;

  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {

	if(tmp->ifa_addr->sa_family==AF_INET) {
		// TODO: Create list of IPs?
	}

	if(tmp->ifa_addr->sa_family==AF_PACKET) {
		printf("Interface: %s\n",tmp->ifa_name);
		if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	  		printf("Creating Socket on interface %s\n",tmp->ifa_name);
			packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(packet_socket<0){
	  		perror("socket");
	  		return 2;
		}
		if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
	  		perror("bind");
		}
      }
    }
  }
  freeifaddrs(ifaddr);
  printf("Ready to recieve now\n");

  while(1){
    char buf[1500];

	struct ether_header eh;
	struct ipheader iph;
	struct arpheader ah;

    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);

    int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
    if(recvaddr.sll_pkttype==PACKET_OUTGOING)
      continue;
    printf("Got a %d byte packet\n", n);
	// Copy ethernet header data from buffer
    memcpy(&eh, &buf, 14);
    eh.ether_type = ntohs(eh.ether_type);

	if (eh.ether_type == ETHERTYPE_ARP) {
		int t_addr, s_addr;
		//Copy ARP data
		memcpy(&ah, &buf[14], 28);
		printf("Got ARP request \n");
		// Copy ARP source and target addresses
		memcpy(&s_addr, ah.spa, 4);
		memcpy(&t_addr, ah.tpa, 4);

		//TODO: Construct and send response
		}
	else if (eh.ether_type == ETHERTYPE_IP) {
		int t_ip;
		memcpy(&iph, &buf[14], 20);
		memcpy(&t_ip, iph.dst_addr, 4);
		
		//TODO: Construct and send response
		}
  }
  return 0;
}
