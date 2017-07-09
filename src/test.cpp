#include <bits/stdc++.h>
#include <pcap.h>
#include <cstdio>

using namespace std;

void getPack(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	int * id = (int * ) arg;
	printf("id: %d\n", ++(*id));
	printf("len: %d\n", pkthdr->len);
	printf("num of bytes: %d\n", pkthdr->caplen);
	printf("time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

	for (size_t i=0;i<pkthdr->len;++i) {
		printf("%02x ", packet[i]);
	}
	puts("\n");
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
