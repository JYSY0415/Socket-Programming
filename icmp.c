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

typedef struct IP_HEADER
{
	unsigned char ip_version_header_lengh;
	unsigned char dsf;
	unsigned short total_length;
	unsigned short identi;
	unsigned short flags;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
}ip_header;

typedef struct ICMP_HDEADER
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short bele;
	unsigned short sn_bele;
	unsigned char timestamp[8];
	unsigned char data[48];
}icmp_header;

int main(void)
{
	struct ifreq if_idx;
	struct sockaddr_ll socket_addr;
	memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
	int socket1;
	unsigned char icmp_packet[1000];
	memset(icmp_packet,0x00,1000);
	ip_header * iphdr=NULL;
	icmp_header * icmphdr=NULL;
	ethernet_header * ethdr=NULL;
	unsigned char ipaddr[4];

	socket1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	strncpy(if_idx.ifr_ifrn.ifrn_name, "eth0", IFNAMSIZ);
	ioctl(socket1, SIOCGIFINDEX, &if_idx);
	
	socket_addr.sll_family = PF_PACKET;
	socket_addr.sll_ifindex = if_idx.ifr_ifru.ifru_ivalue;
	
	ethdr=(ethernet_header*)icmp_packet;
		
	ethdr->dst[0]=0x00;
	ethdr->dst[1]=0x50;
	ethdr->dst[2]=0x56;
	ethdr->dst[3]=0xef;
	ethdr->dst[4]=0xf1;
	ethdr->dst[5]=0xad;	
	
	ethdr->src[0]=0x00;
	ethdr->src[1]=0x0c;
	ethdr->src[2]=0x29;
	ethdr->src[3]=0x43;
	ethdr->src[4]=0xf6;
	ethdr->src[5]=0x06;

	ethdr->type=0x0008;	
	
	iphdr=(ip_header*)&icmp_packet[sizeof(ethernet_header)];

	printf("Target IP : ");
	scanf("%d.%d.%d.%d", &iphdr->dst_ip[0], &iphdr->dst_ip[1], &iphdr->dst_ip[2], &iphdr->dst_ip[3]);

	iphdr->ip_version_header_lengh=0x45;
	iphdr->dsf=0x00;
	iphdr->total_length=0x5400;
	iphdr->identi=0xe86d;
	iphdr->flags=0x0000;
	iphdr->ttl=128;
	iphdr->protocol=0x01;
	//iphdr->checksum=??

	

	icmphdr=(icmp_header*)&icmp_packet[sizeof(ip_header)+sizeof(ethernet_header)];

	icmphdr->type=8;
	icmphdr->code=0;
	icmphdr->checksum=0xf60c;
	icmphdr->bele=0x0100;
	icmphdr->sn_bele=0x0600;
	
	for(int i=0;i<48;i++)
	{
		icmphdr->data[i]=0x08+i;
	}

	

	while(1)
	{	
		srand(time(NULL));
		iphdr->src_ip[0]=rand()%255+1;
		iphdr->src_ip[1]=rand()%255;
		iphdr->src_ip[2]=rand()%255;
		iphdr->src_ip[3]=rand()%255;
		sleep(1);
		sendto(socket1, icmp_packet, sizeof(ethernet_header) + sizeof(ip_header) + sizeof(icmp_header), 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
	}
	
}
