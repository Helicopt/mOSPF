#include "test.h"

int main() {
	if_init();
	if (inters.size()==0||inters[0]->sock<0) {
		cerr<<"wrong"<<endl;
		exit(1);
	}
	in_addr_t dst=inet_addr("224.0.0.5");
	u_char buf[32768];
	EthPack *eth = (EthPack *)buf;
	IPPack *ipp = eth->IP();
	OSPFPack *ospf = ipp->OSPF();
	int len = gen_hello(ospf, inters[0]);
	sendPack(inters[0]->sock,dst,len,ospf);
	exit(233);

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
