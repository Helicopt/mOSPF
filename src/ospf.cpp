#include "ospf.h"

#define GETSEG(v,t,o) t * v = (t*)((u_char*)ospf+(o))

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
	*interval = htons(it->hello_itv);
	*option = 0x02;
	*rtrpri = 0x01;
	*rdi = htonl(it->inac_itv);
	*dr = it->dr;
	*bdr = it->bdr;
	int len = 44;
	for (size_t i=0;i<it->nbs.size();++i) {
		in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
		*rdd = it->nbs[i]->rid;
		len+=4;
	}
	ospf->len=htons(len);
	ospf->chksum=0;
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}

int gen_dd(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=2;
	ospf->rid=inters[0]->ip;
	ospf->aid=it->aid;
	ospf->autp=0x0000;
	ospf->auth=0;
	GETSEG(dd,INT16,24);
	GETSEG(option,u_char,26);
	GETSEG(flags,u_char,27);
	GETSEG(seq,INT32,28);
	*dd = htons(1500);
	*option = 0x02;
	*flags = 0x00;
	*seq = 0x00;
	int len = 32;
	// for (size_t i=0;i<it->nbs.size();++i) {
	// 	in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
	// 	*rdd = it->nbs[i]->rid;
	// 	len+=4;
	// }
	ospf->len=htons(len);
	ospf->chksum=0;
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}

int gen_lsr(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=3;
	ospf->rid=inters[0]->ip;
	ospf->aid=it->aid;
	ospf->autp=0x0000;
	ospf->auth=0;
	int len = 24;
	// for (size_t i=0;i<it->nbs.size();++i) {
	// 	in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
	// 	*rdd = it->nbs[i]->rid;
	// 	len+=4;
	// }
	ospf->len=htons(len);
	ospf->chksum=0;
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}

int gen_lsu(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=4;
	ospf->rid=inters[0]->ip;
	ospf->aid=it->aid;
	ospf->autp=0x0000;
	ospf->auth=0;
	GETSEG(num,INT32,24);
	*num = htonl(0);
	int len = 28;
	// for (size_t i=0;i<it->nbs.size();++i) {
	// 	in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
	// 	*rdd = it->nbs[i]->rid;
	// 	len+=4;
	// }
	ospf->len=htons(len);
	ospf->chksum=0;
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}

int gen_lsack(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=5;
	ospf->rid=inters[0]->ip;
	ospf->aid=it->aid;
	ospf->autp=0x0000;
	ospf->auth=0;
	int len = 24;
	// for (size_t i=0;i<it->nbs.size();++i) {
	// 	in_addr_t * rdd = (in_addr_t*)((u_char*)ospf+len);
	// 	*rdd = it->nbs[i]->rid;
	// 	len+=4;
	// }
	ospf->len=htons(len);
	ospf->chksum=0;
	ospf->chksum=chksum_16((INT16*)ospf, len);
	return len;
}

int deal_hello(inter * it, OSPFPack * ospf) {

	return 0;
}
int deal_dd(inter * it, OSPFPack * ospf) {

	return 0;
}
int deal_lsr(inter * it, OSPFPack * ospf) {

	return 0;
}
int deal_lsu(inter * it, OSPFPack * ospf) {

	return 0;
}
int deal_lsack(inter * it, OSPFPack * ospf) {

	return 0;
}
