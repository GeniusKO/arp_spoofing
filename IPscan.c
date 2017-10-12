#include"IPscan.h"

a_info info;
t_info target;
pcap_t *fp;
u_char *data;
BOOL chk_flag = TRUE;
int target_count = 0;
char buf[32] = { 0, }, buf2[32] = { 0, };

DWORD WINAPI broadcast(void *arg) {

	int i, j, k;
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	u_char *bro_data = (u_char*)malloc(sizeof(u_char) * ARP_HEADER_LEN);
	while (chk_flag);
	for (i = 0; i < ARP_HEADER_LEN; i++) *(bro_data + i) = *(data + i);
	while (1) {
		if (chk_flag) break;
		eh = (struct libnet_ethernet_hdr *)bro_data;
		ah = (struct libnet_arp_hdr *)bro_data;

		for (i = 0; i < ETHER_ADDR_LEN; i++) *(bro_data + i) = 0xff;
		for (j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(bro_data + i) = info.Host_Mac[j];
		bro_data += sizeof(*eh) + sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(bro_data + 1) = ARPOP_REQUEST;
		bro_data += sizeof(ah->ar_op);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(bro_data + i) = info.Host_Mac[i];
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_spa); i++, j++) *(bro_data + i) = info.Host_Ip[j];
		bro_data += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for (i = 0; i < ETHER_ADDR_LEN; i++) *(bro_data + i) = 0x00;
		for (j = 0; i < ETHER_ADDR_LEN + sizeof(ah->ar_tpa) - 1; j++, i++) {
			*(bro_data + i) = info.Router_Ip[j];
		}
		bro_data += sizeof(ah->ar_tha) + 3;
		for (k = 1; k < BROADCAST; k++) {
			*(bro_data) = k;
			bro_data -= sizeof(*eh) + (sizeof(*ah) - 1);
			if (pcap_sendpacket(fp, bro_data, ARP_HEADER_LEN) != 0) {
				printf("Error\n");
				return -1;
			}
			bro_data += sizeof(*eh) + sizeof(*ah) - 1;
		}
		bro_data -= sizeof(*eh) + sizeof(*ah) - 1;
		Sleep(10000);
	}
	setTargetList(target);
	free(bro_data);
	return 0;
}

int target_search(struct libnet_arp_hdr *ah) {
	int i;
	int result = 0;

	for (i = 0; i < target_count; i++) {
		if (!strncmp(inet_ntop(AF_INET, &target.target_ip[i], buf2, sizeof(buf2)), inet_ntop(AF_INET, &ah->ar_spa, buf, sizeof(buf)), 4)) {
			if (!strcmp(inet_ntop(AF_INET, &target.target_mac[i], buf2, sizeof(buf2)), inet_ntop(AF_INET, &ah->ar_sha, buf, sizeof(buf)))) {
				result = 1;
			}
		}
	}
	if (strcmp(inet_ntop(AF_INET, &info.Router_Ip, buf2, sizeof(buf2)), inet_ntop(AF_INET, &ah->ar_spa, buf, sizeof(buf))) == 0) {
		result = 1;
	}
	if (strcmp(inet_ntop(AF_INET, &info.Host_Ip, buf2, sizeof(buf2)), inet_ntop(AF_INET, &ah->ar_spa, buf, sizeof(buf))) == 0) {
		result = 1;
	}
	return result;
}

int broadcast_reply(struct libnet_arp_hdr *ah) {
	int i;

	if (!strncmp(inet_ntop(AF_INET, &info.Host_Ip, buf2, sizeof(buf2)), inet_ntop(AF_INET, &ah->ar_tpa, buf, sizeof(buf)), 4)) {
		if (target_search(ah) == 0) {
			for (i = 0; i < 4; i++) target.target_ip[target_count][i] = ah->ar_spa[i];
			printf("\t%d.\tTarget IP : %s\t Target MAC : ", target_count + 1, inet_ntop(AF_INET, &target.target_ip[target_count], buf, sizeof(buf)));
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				target.target_mac[target_count][i] = ah->ar_sha[i];
				if (i == 5) printf("%02X\n", target.target_mac[target_count][i]);
				else printf("%02X-", target.target_mac[target_count][i]);
			}
			target_count++;
			return 1;
		}
	}
	return 0;
}

void setpcapData_scan(pcap_t *return_fp, a_info return_info) {
	fp = return_fp;
	info = return_info;
}

void setBroadcastFlag(BOOL flag, u_char *pkt) {
	chk_flag = flag;
	data = pkt;
}
