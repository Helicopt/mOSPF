#include <bits/stdc++.h>
#include <pcap.h>
#include <cstdio>

using namespace std;

int main() {
    char buff[PCAP_ERRBUF_SIZE], *device;

    device = pcap_lookupdev(buff);
    if (device) {
        printf("device: %s\n", device);
        pcap_t * dev = pcap_open_live(device, 65535, 1, 0, buff);
        struct pcap_pkthdr packet;
        const u_char * pktStr = pcap_next(dev, &packet);
        if (pktStr) {
            cout<<packet.len<<endl;
            pcap_close(dev);
        }
    } else puts(buff);
    return 0;
}
