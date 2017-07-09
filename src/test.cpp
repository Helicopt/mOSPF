#include <bits/stdc++.h>
#include <pcap.h>
#include <cstdio>

using namespace std;

typedef unsigned short INT16;
typedef unsigned int INT32;

struct EthPack {
	u_char src[6], dst[6];
	u_char tp[2];
	u_char * data;
	EthPack(const u_char * d) {
		memcpy(src,d,6);
		memcpy(dst,d+6,6);
		memcpy(tp,d+12,2);
		data = (u_char *)(d+14);
	}
	EthPack(){}
	void print() {
		printf("source addr: ");
		for (int i=0;i<6;++i) printf("%02x ", src[i]);
		printf("destination addr: ");
		for (int i=0;i<6;++i) printf("%02x ", dst[i]);
		printf("\n%02x %02x ...\n", tp[0], tp[1]);
	}
};

struct IPPack {
	u_char ver, h_len, ds;
	INT16 len, id;
	u_char flags;
	INT16 offs;
	u_char ttl, protocol;
	INT16 chksum;
	INT32 src, dst;
	u_char * data;
	EthPack super;
	IPPack (const EthPack & p) {
		super = p;
		u_char * d=p.data;
		ver = (*d)>>4;
		h_len = (*d)&0xF;
		ds = *(d+1);
		len = (*(d+2)<<8)+(*(d+3));
		id = (*(d+4)<<8)+(*(d+5));
		flags = *(d+6)>>5;
		offs = (((*d+6)&0x1f)<<8)+(*(d+7));
		ttl = *(d+8);
		protocol = *(d+9);
		chksum = (*(d+10)<<8)+(*(d+11));
		src = *((INT32 *)(d+12));
		dst = *((INT32 *)(d+16));
		data = d+20;
	}
	IPPack(){}
	void print() {
		if (ver==4) puts("IPv4");
		else puts("IP v ?");
		printf("head length: %d total length: %d\n", h_len, len);
		if (protocol==89) puts("OSPF v2");
		else puts("other");
		printf("src: %d.%d.%d.%d, dst: %d.%d.%d.%d\n",src>>24,(src>>16)&0xff,(src>>8)&0xff,src&0xff, dst>>24,(dst>>16)&0xff,(dst>>8)&0xff,dst&0xff);
	}
};

struct OSPFPack {
	u_char ver, tp;
	INT16 len;
	INT32 rid, aid;
	INT16 chksum, autp;
	INT32 auth;
	u_char * data;
	IPPack super;
	OSPFPack (const IPPack & p) {
		if (p.protocol!=89) {
			ver = 0xff;
		} else {
			super = p;
			u_char * d = p.data;
			ver = *d;
			tp = *(d+1);
			len = (*(d+2)<<8)+(*(d+3));
			rid = *((INT32 *)(d+4));
			aid = *((INT32 *)(d+8));
			chksum = (*(d+12)<<8)+(*(d+13));
			autp = (*(d+14)<<8)+(*(d+15));
			auth = *((INT32 *)(d+16));
			data = d+20;
		}
	}
	OSPFPack(){}
	void print() {
		if (ver==0xff) puts("is not ospf");
		else {
			switch (tp) {
				case 1: puts("Hello");break;
				case 2: puts("DD");break;
				case 3: puts("LSR");break;
				case 4: puts("LSU");break;
				case 5: puts("LSAck");break;
				default:puts("Unknown");
			}
			printf("Router ID: %u, Area ID: %u\n", rid, aid);
		}
	}
};

void getPack(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	int * id = (int * ) arg;
	printf("id: %d\n", ++(*id));
	printf("len: %d\n", pkthdr->len);
	printf("num of bytes: %d\n", pkthdr->caplen);
	printf("time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
	EthPack ep(packet);
	ep.print();
	IPPack ipp(ep);
	ipp.print();
	OSPFPack opp(ipp);
	opp.print();
	puts("----------------");
}

int main() {
    char buff[PCAP_ERRBUF_SIZE], *device;

    device = pcap_lookupdev(buff);
    if (device) {
        printf("device: %s\n", device);
        pcap_t * dev = pcap_open_live(device, 65535, 1, 0, buff);
		int id = 0;
		pcap_loop(dev, -1, getPack, (u_char*)&id);
		pcap_close(dev);
    } else puts(buff);
    return 0;
}
