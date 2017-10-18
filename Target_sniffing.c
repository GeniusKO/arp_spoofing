#include "IPscan.h"

t_info v_target;
a_info v_info;
int s_target = 0;
BOOL _flag = TRUE;
u_char *d_name;

DWORD WINAPI target_paket_capture(u_char *name) {
	
	pcap_t *fp;
	pcap_if_t *alldevs;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	struct libnet_ethernet_hdr *eh;
	//struct libnet_arp_hdr *ah;
	struct libnet_ipv4_hdr *ih;
	struct libnet_tcp_hdr *th;
	char buf[32] = { 0, }, buf2[32] = { 0, }, errbuf[PCAP_ERRBUF_SIZE];
	int res, cnt = 0, th_off = 0;
	while (_flag);
	
	if ((fp = pcap_open_live(name, 65536, 1, 20, errbuf)) == NULL) { // My adapter Open
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		if (header->len != header->caplen) {
			printf("pcap file error\n");
			exit(1);
		}
		eh = (struct libnet_ethernet_hdr *)pkt_data;
		//ah = (struct libnet_arp_hdr *)(pkt_data + sizeof(*eh));
		ih = (struct libnet_ipv4_hdr *)(pkt_data + sizeof(*eh));
		th = (struct libnet_tcp_hdr *)(pkt_data + sizeof(*eh) + sizeof(*ih));
		if (!strncmp(v_info.Host_Mac, eh->ether_dhost, 6) && !strncmp(v_target.target_mac, eh->ether_shost, 6) && ntohs(eh->ether_type) == ETHERTYPE_IP && ih->ip_p == IPPROTO_TCP && th->th_dport == HTTP_PORT) {
			th_off = th->th_off * 4;
			if (th_off > LIBNET_TCP_H) {
				printf("1. Dst MAC: ");
				for (int i = 0; i < 6; i++) { // Destination mac address 6byte
					if (i == 5) printf("%02x | ", eh->ether_dhost[i]);
					else printf("%02x:", eh->ether_dhost[i]);
				}
				printf("Src MAC: ");
				for (int i = 0; i < 6; i++) { // source mac address 6byte
					if (i == 5) printf("%02x | ", eh->ether_shost[i]);
					else printf("%02x:", eh->ether_shost[i]);
				}
				printf("\tDst IP Addr : %s | ", inet_ntop(AF_INET, &ih->ip_dst, buf, sizeof(buf)));
				printf("Src IP Addr : %s\n", inet_ntop(AF_INET, &ih->ip_src, buf, sizeof(buf)));
				pkt_data += sizeof(*eh) + sizeof(*ih) + th_off;
				printf("%s\n", pkt_data);
			}
			else {
				printf("1. Dst MAC: ");
				for (int i = 0; i < 6; i++) { // Destination mac address 6byte
					if (i == 5) printf("%02x | ", eh->ether_dhost[i]);
					else printf("%02x:", eh->ether_dhost[i]);
				}
				printf("Src MAC: ");
				for (int i = 0; i < 6; i++) { // source mac address 6byte
					if (i == 5) printf("%02x | ", eh->ether_shost[i]);
					else printf("%02x:", eh->ether_shost[i]);
				}
				printf("\tDst IP Addr : %s | ", inet_ntop(AF_INET, &ih->ip_dst, buf, sizeof(buf)));
				printf("Src IP Addr : %s\n", inet_ntop(AF_INET, &ih->ip_src, buf, sizeof(buf)));
				pkt_data += sizeof(*eh) + sizeof(*ih) + sizeof(*th);
				printf("%s\n", pkt_data);
			}
		}
	}
}

void setSniffingData(BOOL flag, a_info return_info, t_info return_target, int number) {
	_flag = flag;
	v_info = return_info;
	v_target = return_target;
	s_target = number;
}