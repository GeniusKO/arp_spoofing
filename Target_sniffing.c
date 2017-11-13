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
		ih = (struct libnet_ipv4_hdr *)(pkt_data + sizeof(*eh));
		th = (struct libnet_tcp_hdr *)(pkt_data + sizeof(*eh) + sizeof(*ih));
		th_off = th->th_off * 4;
		
		if (!strcmp(inet_ntop(AF_INET, &ih->ip_dst, buf, sizeof(buf)), inet_ntop(AF_INET, &v_target.target_ip[s_target], buf2, sizeof(buf2))) || !strcmp(inet_ntop(AF_INET, &ih->ip_src, buf, sizeof(buf)), inet_ntop(AF_INET, &v_target.target_ip[s_target], buf2, sizeof(buf2)))) {
			if (th ->th_dport == HTTP_PORT || th->th_sport == HTTP_PORT) {
				pkt_data += sizeof(*eh) + sizeof(*ih) + th_off;
				printf("%s\n", pkt_data);
			}
		}
	}

	pcap_freealldevs(alldevs);
	return 0;
}

void setSniffingData(BOOL flag, a_info return_info, t_info return_target, int number) {
	_flag = flag;
	v_info = return_info;
	v_target = return_target;
	s_target = number;
}