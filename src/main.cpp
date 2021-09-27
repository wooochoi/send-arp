#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>

#define REQUEST 1
#define REPLY 2
#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

EthArpPacket packet;

char myip[20];
unsigned char mymac[6];
unsigned char yourmac[6];

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int32_t getmyip(char* dev, char* myip){
	struct ifreq ifr;
	char myipstr[20];
	u_int32_t s;

	printf("getmyip start\n");
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ioctl(s, SIOCGIFADDR, &ifr);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, myipstr, sizeof(struct sockaddr));
	printf("my IP address is %s\n", myipstr);
	memcpy(myip, myipstr, strlen(myipstr));
	printf("getmyip end\n");

	return 0;
}

void getmymac(char *dev, unsigned char* mymac){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	printf("getmymac start\n");

	memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
	printf("my MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	printf("getmymac end\n");
}

int sendarp(pcap_t* handle, char* sender_ip, char* target_ip, unsigned char* mymac, unsigned char* yourmac, uint16_t op) {

	printf("sendarp start\n");
	if (op == REQUEST) {
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.op_ = htons(ArpHdr::Request);
	} 
	else if (op == REPLY) {
		packet.eth_.dmac_ = Mac(yourmac);
		packet.arp_.tmac_ = Mac(yourmac);
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tip_ = htonl(Ip(target_ip));

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
		fprintf(stderr, "couldn't send packet : %s\n", pcap_geterr(handle));
		return -1;
	}

	printf("send arp from '%s' to '%s'\n",sender_ip,target_ip);
	printf("my mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);
	printf("your mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", yourmac[0],yourmac[1],yourmac[2],yourmac[3],yourmac[4],yourmac[5]);

	printf("sendarp end\n");
	return 0;
}

int getyourmac(pcap_t* handle, char* myip, char* yourip, unsigned char* mymac,unsigned char* yourmac){
	printf("getyourmac start\n");
    while(true){
        sendarp(handle, myip, yourip, mymac, yourmac, REQUEST);
		struct pcap_pkthdr* header;
		const u_char* _packet;
		
		int res = pcap_next_ex(handle, &header, &_packet);

		EthHdr* eth_ = (EthHdr*) _packet;
	
		ArpHdr* arp_ = (ArpHdr*) ((uint8_t*)(_packet) + 14);
		
		memcpy(yourmac,(u_char*)arp_->smac_, 6);
		printf("your mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", yourmac[0],yourmac[1],yourmac[2],yourmac[3],yourmac[4],yourmac[5]);
		break;
    }
	printf("getyourmac end\n");
	return 0;
}   

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	getmyip(dev, myip);
	getmymac(dev, mymac);

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	getyourmac(handle, myip, argv[2], mymac, yourmac);
	sendarp(handle, argv[2], argv[3], mymac, yourmac, REPLY);

	pcap_close(handle);
}
