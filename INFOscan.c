#include"IPscan.h"

a_info info;


void change(char *ip_addr, int mode) {
	int tmp;
	int i, j;
	int cnt = 0;
	for (j = 0; j < 4; j++) {
		tmp = 0;
		for (i = cnt; i < 16; i++) {
			if (isdigit(*(ip_addr + i))) {
				tmp *= 10;
				tmp += *(ip_addr + i) - '0';
			}
			else
				break;
		}
		cnt = i + 1;
		if (mode == 1) sprintf(&info.Host_Ip[j], "%c", tmp);
		else if (mode == 2) sprintf(&info.Router_Ip[j], "%c", tmp);
	}
}

int search_Info(u_char *name) {

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	u_long dwRetVal = 0;
	u_int i;
	char buf[32] = { 0, };

	// My Ip and Mac, Gateway(Router) Search
	u_long ulOutBufLen = sizeof(IP_ADAPTER_INFO); // error buffer
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO)); // pAdapterInfo에 메모리 동적 할당
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo); // 에러시 메모리 해제
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen); // 오버된 만큼 메모리 재 설정
		if (pAdapterInfo == NULL) { // 재검사
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) { // 재실행
		pAdapter = pAdapterInfo; // 같은 구조체에 값을 넘겨줌
		while (pAdapter) {
			if (!strcmp(name + 12, pAdapter->AdapterName)) { // 선택한 네트워크 어댑터와 같은 것만 출력
				printf("\tMac Addr: \t");
				for (i = 0; i < pAdapter->AddressLength; i++) {
					info.Host_Mac[i] = *(pAdapter->Address + i);
					if (i == (pAdapter->AddressLength - 1))
						printf("%02X\n", info.Host_Mac[i]);
					else
						printf("%02X-", info.Host_Mac[i]);
				}
				change(pAdapter->IpAddressList.IpAddress.String, 1);
				change(pAdapter->GatewayList.IpAddress.String, 2);
				printf("\tIP Address: \t%s\n", inet_ntop(AF_INET, &info.Host_Ip, buf, sizeof(buf)));
				printf("\tGateway   : \t%s\n", inet_ntop(AF_INET, &info.Router_Ip, buf, sizeof(buf)));
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
	}
	if (pAdapterInfo)
		free(pAdapterInfo);

	return 0;
	// end
}

a_info *getAdapterInfo() {
	return &info;
}