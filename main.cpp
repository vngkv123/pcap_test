#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

#define   IP_TEMP_SIZE 0x40

#define   ICMP 1
#define   IGMP 2
#define   GGP 3
#define   IP_IN_IP 4
#define   ST 5
#define   TCP 6
#define   CBT 7

/* so many protocol type ! */
/* https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers */

typedef struct ether_header eth;
typedef struct mac_addr{
  uint8_t bytes[6];
} mac_addr;

struct ip{
  uint8_t bytes[4];
};

typedef struct ip_header{
  uint8_t version_IHL;
  uint8_t tos;
  uint16_t total_length;
  uint16_t identi;
  uint16_t dummy;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  struct ip source_ip;
  struct ip dest_ip;
  uint32_t ip_option;
} ip_header;

typedef struct tcp_header{
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq_number;
  uint32_t ack_number;
  uint16_t dummy;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_p;
  uint32_t tcp_option;
} tcp_header;

typedef struct udp_header{
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} udp_header;

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void PacketCallbackFunction(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
void PacketMacPrint(mac_addr * dat);

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
		struct pcap_pkthdr* header;
		const u_char* pkt_data;

  int res = 0;
	while((res=pcap_next_ex(handle, &header,&pkt_data))>=0){
		if (res==0) continue;
    PacketCallbackFunction(0, header, pkt_data);
	}

	pcap_close(handle);
	return 0;
}

void PacketCallbackFunction(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *pkt_data){
  eth* eptr = (eth *)pkt_data;

  char *tempIPSetter_1 = (char *)malloc(IP_TEMP_SIZE);
  char *tempIPSetter_2 = (char *)malloc(IP_TEMP_SIZE);

  if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
    ip_header * ip = (ip_header *)(pkt_data + 14);
    uint8_t ip_length = (ip->version_IHL & 0xf) << 2;
    mac_addr * source_mac = (mac_addr *)(pkt_data);
    mac_addr * dest_mac = (mac_addr *)(pkt_data + 6);
    printf("----------------------------------------------\n");
    printf("Source MAC : ");
    PacketMacPrint(source_mac);
    printf("Dest MAC : ");
    PacketMacPrint(dest_mac);
    if(ip->protocol == TCP){ // TCP
      tcp_header * tcp = (tcp_header *)(ip + ip_length);
      printf("Source IP :");
      inet_ntop(AF_INET,(void *)(&ip->source_ip), tempIPSetter_1, IP_TEMP_SIZE);
      printf("%s\n",tempIPSetter_1);
      printf("Port : %d\n",ntohs(tcp->source_port));
      printf("Dest IP :");
      inet_ntop(AF_INET,(void*)(&ip->dest_ip), tempIPSetter_2, IP_TEMP_SIZE);
      printf("%s\n", tempIPSetter_2);
      printf("Port : %d\n", ntohs(tcp->dest_port));
      uint8_t i;
      pkt_data += sizeof(eth) + sizeof(ip_header) + sizeof(tcp_header);

      for(i = 0; (i < header->len + 1) && i < 16; i++){
           if((pkt_data[i] >= 33) && (pkt_data[i] <= 126))
                printf(" %c", pkt_data[i]);
           else
                printf(".");
      }
      puts("\n");

    }
    else{
      printf("[-] Another type\n");
    }
    printf("----------------------------------------------\n");
  }

  free(tempIPSetter_1);
  free(tempIPSetter_2);
}

void PacketMacPrint(mac_addr * dat){
  printf("%x:%x:%x:%x:%x:%x",dat->bytes[0],dat->bytes[1],dat->bytes[2],dat->bytes[3],dat->bytes[4],dat->bytes[5]);
  puts("\n");
  return;
}
