#ifndef __IPSCAN_H__
#define __IPSCAN_H__

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<pcap.h>
#include<libnet.h>
#include<iphlpapi.h>

#define IP_ADDR_LEN 4
#define BROADCAST 255
#define ARP_HEADER_LEN 42
#define HTTP_PORT 0x5000

#define BOOL unsigned char
#define TRUE 1
#define FALSE 0

CRITICAL_SECTION crt;

#pragma pack(push,1)
typedef struct Adapter_Info {
	u_char Host_Mac[ETHER_ADDR_LEN];
	u_char Host_Ip[IP_ADDR_LEN];
	u_char Router_Mac[ETHER_ADDR_LEN];
	u_char Router_Ip[IP_ADDR_LEN];
}a_info;

typedef struct Target {
	u_char target_ip[BROADCAST][IP_ADDR_LEN];
	u_char target_mac[BROADCAST][ETHER_ADDR_LEN];
}t_info;
#pragma pack(pop)

int search_Info(u_char *name);
void change(char *ip_addr, int mode);
int broadcast_reply(struct libnet_arp_hdr *ah);
int target_search(struct libnet_arp_hdr *ah);
a_info *getAdapterInfo();

void setTargetList(t_info return_target);
void setpcapData_scan(pcap_t *return_fp, a_info return_info);
void setpcapData_relay(pcap_t *return_fp, a_info return_info);
void setBroadcastFlag(BOOL flag, u_char *pkt);
void setSendingFlag(BOOL flag, u_char *pkt, int num);
void setSniffingData(BOOL flag, a_info return_info, t_info return_target, int number);

DWORD WINAPI broadcast(void *arg);
DWORD WINAPI sending_vic_request(void *arg);
DWORD WINAPI sending_vic_reply(void *arg);
DWORD WINAPI sending_rou_request(void *arg);
DWORD WINAPI sending_rou_reply(void *arg);
DWORD WINAPI target_paket_capture(u_char *name);

#endif // !__IPSCAN_H__