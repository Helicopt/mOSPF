#ifndef common_h
#define common_h
#include <bits/stdc++.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>

using namespace std;

typedef unsigned short INT16;
typedef unsigned int INT32;

struct OSPFPack {
	u_char ver, tp;
	INT16 len;
	INT32 rid, aid;
	INT16 chksum, autp;
	INT32 auth;
	void print() {
		if (ver!=2&&ver!=1) puts("is not ospf");
		else {
			switch (tp) {
				case 1: puts("Hello");break;
				case 2: puts("DD");break;
				case 3: puts("LSR");break;
				case 4: puts("LSU");break;
				case 5: puts("LSAck");break;
				default:puts("Unknown");
			}
			printf("Router ID: %s, Area ID: %s\n", inet_ntoa((in_addr){rid}), inet_ntoa((in_addr){aid}));
		}
	}
};

struct IPPack {
	u_char v_hl, ds;
	INT16 len, id;
	INT16 flag_off;
	u_char ttl, protocol;
	INT16 chksum;
	INT32 src, dst;
	void print() {
		if ((v_hl>>4)==4) puts("IPv4");
		else puts("IP v ?");
		printf("head length: %d total length: %d\n", v_hl&0xf, len);
		if (protocol==89) puts("OSPF v2");
		else puts("other");
		printf("src: %d.%d.%d.%d, dst: %d.%d.%d.%d\n",src>>24,(src>>16)&0xff,(src>>8)&0xff,src&0xff, dst>>24,(dst>>16)&0xff,(dst>>8)&0xff,dst&0xff);
	}
	OSPFPack * OSPF() {return (OSPFPack *)((u_char*)this+20);};
};

struct EthPack {
	u_char dst[6], src[6];
	u_char tp[2];
	void print() {
		printf("source addr: ");
		for (int i=0;i<6;++i) printf("%02x ", src[i]);
		printf("destination addr: ");
		for (int i=0;i<6;++i) printf("%02x ", dst[i]);
		printf("\n%02x %02x ...\n", tp[0], tp[1]);
	}
	IPPack * IP() {return (IPPack *)((u_char*)this+14);};
};

struct neib
{
	in_addr_t ip, rid;
	int s;
	int inac_cnt, dd_cnt;
};

struct inter
{
	char dn [32];
	int s, sock;
	in_addr_t mask, ip, aid, dr, bdr;
	vector<neib *> nbs;
	int hello_cnt, hello_itv;
	int inac_itv, dd_itv;
};

struct route
{
	in_addr_t ip, mask, nxt;
	int cost;
};


void if_init();
void sendPack(int socket_fd, in_addr_t dst, int len, void * data);
INT16 chksum_16(INT16 * d, int len);

extern vector<inter *> inters;

#endif