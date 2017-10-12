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
	struct libnet_arp_hdr *ah;
	char buf[32] = { 0, }, buf2[32] = { 0, }, errbuf[PCAP_ERRBUF_SIZE];
	int res, cnt = 0;
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
		ah = (struct libnet_arp_hdr *)(pkt_data + sizeof(*eh));
		if (!strncmp(v_info.Host_Mac, eh->ether_dhost, 6) && !strncmp(inet_ntop(AF_INET, &v_info.Router_Ip, buf, sizeof(buf)), inet_ntop(AF_INET, &ah->ar_tpa, buf2, sizeof(buf2)), 4)) {
			if (!strncmp(v_target.target_mac[s_target], eh->ether_shost, 6) && !strncmp(inet_ntop(AF_INET, &v_target.target_ip[s_target], buf, sizeof(buf)), inet_ntop(AF_INET, &ah->ar_spa, buf2, sizeof(buf2)), 4)) {
				if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
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
					printf("\tDst IP Addr : %s | ", inet_ntop(AF_INET, &ah->ar_tpa, buf, sizeof(buf)));
					printf("Src IP Addr : %s\n", inet_ntop(AF_INET, &ah->ar_spa, buf, sizeof(buf)));
				}
			}
		}
		if (!strncmp(v_info.Host_Mac, eh->ether_dhost, 6) && !strncmp(inet_ntop(AF_INET, &v_target.target_ip[s_target], buf, sizeof(buf)), inet_ntop(AF_INET, &ah->ar_tpa, buf2, sizeof(buf2)), 4)) {
			if (!strncmp(v_info.Router_Mac, eh->ether_shost, 6) && !strncmp(inet_ntop(AF_INET, &v_info.Router_Ip, buf, sizeof(buf)), inet_ntop(AF_INET, &ah->ar_spa, buf2, sizeof(buf2)), 4)) {
				if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
					printf("%s\n", inet_ntop(AF_INET, &v_target.target_ip[s_target], buf, sizeof(buf)));
					printf("2. Dst MAC: ");
					for (int i = 0; i < 6; i++) { // Destination mac address 6byte
						if (i == 5) printf("%02x | ", eh->ether_dhost[i]);
						else printf("%02x:", eh->ether_dhost[i]);
					}
					printf("Src MAC: ");
					for (int i = 0; i < 6; i++) { // source mac address 6byte
						if (i == 5) printf("%02x | ", eh->ether_shost[i]);
						else printf("%02x:", eh->ether_shost[i]);
					}
					printf("\tDst IP Addr : %s | ", inet_ntop(AF_INET, &ah->ar_tpa, buf, sizeof(buf)));
					printf("Src IP Addr : %s\n", inet_ntop(AF_INET, &ah->ar_spa, buf, sizeof(buf)));
				}
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