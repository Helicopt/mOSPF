#include "test.h"
#include <pthread.h>
#include <unistd.h>

in_addr_t dst, dr_dst;

void * send_loop(void * x) {
	u_char buf[32768];
	EthPack *eth = (EthPack *)buf;
	IPPack *ipp = eth->IP();
	OSPFPack *ospf = ipp->OSPF();
	while (1) {
		for (size_t i=0;i<inters.size();++i) {
			inter * it = inters[i];
			vector<neib *> new_nbs;
			for (size_t j=0;j<it->nbs.size();++j) {
				neib * nb = it->nbs[j];
				nb->inac_cnt++;
				if (nb->inac_cnt>=it->inac_itv) {
					free(nb);
				} else new_nbs.push_back(nb);
			}
			it->nbs = new_nbs;
			if (it->hello_cnt==0) {
				int len=gen_hello(ospf, it);
				sendPack(it->sock,dst,len,ospf);
			}
			it->hello_cnt++;
			it->hello_cnt%=it->hello_itv;
			for (size_t j=0;j<it->nbs.size();++j) {
				neib * nb = it->nbs[j];
				nb->dd_cnt++;
				if (nb->dd_cnt>=it->dd_itv) {
					
				}
				if (nb->s) {
					
				}
			}

		}
		// int len = gen_hello(ospf, inters[0]);
		// sendPack(inters[0]->sock,dst,len,ospf);
		// len = gen_dd(ospf, inters[0]);
		// sendPack(inters[0]->sock,dst,len,ospf);
		// len = gen_lsr(ospf, inters[0]);
		// sendPack(inters[0]->sock,dst,len,ospf);
		// len = gen_lsu(ospf, inters[0]);
		// sendPack(inters[0]->sock,dst,len,ospf);
		// len = gen_lsack(ospf, inters[0]);
		// sendPack(inters[0]->sock,dst,len,ospf);
		sleep(1);	
	}
}

void getPack(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	// int * id = (int * ) arg;
	// printf("id: %d\n", ++(*id));
	// printf("len: %d\n", pkthdr->len);
	// printf("num of bytes: %d\n", pkthdr->caplen);
	// printf("time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
	// // for (int i=0;i<pkthdr->caplen;++i) printf("%02x ", packet[i]);
	EthPack *ep = (EthPack *)packet;
	// ep->print();
	IPPack *ipp = ep->IP();
	// ipp->print();
	// printf("!!%02x", ipp->v_hl);
	OSPFPack *opp = ipp->OSPF();
	// opp->print();
	inter * itt;
	if (opp->ver==2&&ipp->protocol==89) {
		opp->print();
		in_addr_t src = ipp->src;
		if (chksum_16((INT16 *)opp, ntohs(opp->len))) return;
		else puts("recved.");
		puts("----------------");
		for (size_t i=0;i<inters.size();++i) {
			inter * it = inters[i];
			if (ipp->src&it->mask==it->ip&it->mask) {
				itt=it;
				break;
			}
		}
		switch (opp->tp) {
			case 1:deal_hello(itt, opp);break;
			case 2:deal_dd(itt, opp);break;
			case 3:deal_lsr(itt, opp);break;
			case 4:deal_lsu(itt, opp);break;
			case 5:deal_lsack(itt, opp);break;
			default:puts("unknown type!");
		}
	}// else printf("%d\n", (ipp->protocol));
}

void * recv_loop(void * x) {
    char buff[PCAP_ERRBUF_SIZE], *device;

    device = pcap_lookupdev(buff);
    if (device) {
        printf("device: %s\n", device);
        pcap_t * dev = pcap_open_live(device, 65535, 1, 0, buff);
		int id = 0;
		pcap_loop(dev, -1, getPack, (u_char*)&id);
		pcap_close(dev);
    } else puts(buff);
}


int main() {
	if_init();
	if (inters.size()==0||inters[0]->sock<0) {
		cerr<<"wrong"<<endl;
		exit(1);
	}
	dst=inet_addr("224.0.0.5");
	dr_dst=inet_addr("224.0.0.6");
	
	int sig = 1;
	pthread_t recv_, send_;
	pthread_create(&recv_, NULL, recv_loop, &sig);
	pthread_create(&send_, NULL, send_loop, &sig);

	pthread_join(recv_, NULL);
	pthread_join(send_, NULL);
    return 0;
}
