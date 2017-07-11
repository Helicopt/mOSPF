#include "common.h"

vector<inter *> inters;

void if_init() {
	ifconf conf;
	ifreq ifreqs[64];
	int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IP));
	conf.ifc_req = ifreqs;
	conf.ifc_len = sizeof(ifreqs);
	ioctl(sock, SIOCGIFCONF, &conf);
	int cnt = conf.ifc_len/sizeof(ifreq);
	for (int i=0;i<cnt;++i) {
		if (strcmp(ifreqs[i].ifr_name,"lo")!=0) {
			inter * it = new inter();
			strcpy(it->dn, ifreqs[i].ifr_name);
			ioctl(sock, SIOCGIFADDR, ifreqs+i);
			it->ip = ((sockaddr_in *)&ifreqs[i].ifr_addr)->sin_addr.s_addr;
			ioctl(sock, SIOCGIFNETMASK, ifreqs+i);
			it->mask = ((sockaddr_in *)&ifreqs[i].ifr_netmask)->sin_addr.s_addr;
			ioctl(sock, SIOCGIFFLAGS, ifreqs+i);
			ifreqs[i].ifr_flags|=IFF_PROMISC;
			ioctl(sock, SIOCGIFFLAGS, ifreqs+i);
			it->sock = socket(AF_INET, SOCK_RAW, 89);
			setsockopt(it->sock, SOL_SOCKET, SO_BINDTODEVICE, ifreqs+i, sizeof(ifreq));
			it->hello_cnt=0;
			it->hello_itv=10;
			it->inac_itv=40;
			it->dd_itv=5;
			it->s=0;
			it->aid=0;
			inters.push_back(it);
		}
	}
}

void sendPack(int socket_fd, in_addr_t dst, int len, void * data) {
	sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dst;
	sendto(socket_fd, data, len, 0, (sockaddr *)&addr, sizeof(addr));
}

INT16 chksum_16(INT16 * d, int len) {
	INT32 res = 0;
	while (len > 1) {
		res+=*d++;
		len-=2;
	}
	if (len) res+=*(u_char*)d;
	res=(res>>16)+(res&0xffff);
	res+=(res>>16);
	return ~res;
}