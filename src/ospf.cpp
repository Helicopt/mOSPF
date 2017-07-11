#include "ospf.h"

int gen_hello(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=1;
	ospf->rid=inters[0]->ip;
	ospf->aid=it->aid;
	ospf->autp=0x0000;
	ospf->auth=0;
	in_addr_t * hello = (in_addr_t*)((u_char*)ospf+24);
	INT16 * interval = (INT16*)((u_char*)ospf+28);
	u_char * option = ((u_char*)ospf+30);
	u_char * rtrpri = ((u_char*)ospf+31);
	INT32 * rdi = (INT32*)((u_char*)ospf+32);
	in_addr_t * dr = (in_addr_t*)((u_char*)ospf+36);
	in_addr_t * bdr = (in_addr_t*)((u_char*)ospf+40);
	*hello = it->mask;
	*interval = htons(10);
	*option = 0x02;
	*rtrpri = 0x01;
	*rdi = htonl(40);
	*dr = it->dr;
	*bdr = it->bdr;
	int len = 44;
	for (size_t i=0;i<it->nbs.size();++i) {
		in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
		*rdd = it->nbs[i]->rid;
		len+=4;
	}
	ospf->len=htons(len);
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}