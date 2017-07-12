#include "ospf.h"

#define GETSEG(v,t,o) t * v = (t*)((u_char*)ospf+(o))

int gen_hello(OSPFPack * ospf, inter * it) {
	ospf->ver=2;
	ospf->tp=1;
	ospf->rid=it->ip;
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
	*rtrpri = 0x00;
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
	ospf->rid=it->ip;
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
	ospf->rid=it->ip;
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
	ospf->rid=it->ip;
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

int deal_hello(inter * it, OSPFPack * ospf, in_addr_t src) {
	in_addr_t * hello = (in_addr_t*)((u_char*)ospf+24);
	INT16 * interval = (INT16*)((u_char*)ospf+28);
	u_char * option = ((u_char*)ospf+30);
	u_char * rtrpri = ((u_char*)ospf+31);
	INT32 * rdi = (INT32*)((u_char*)ospf+32);
	in_addr_t * dr = (in_addr_t*)((u_char*)ospf+36);
	in_addr_t * bdr = (in_addr_t*)((u_char*)ospf+40);
	in_addr_t * nbrs = (in_addr_t*)((u_char*)ospf+44);
	int nb_cnt = (ospf->len-44)>>2;
	neib * nb = NULL;
	puts("doing hello");
	for (size_t i=0;i<it->nbs.size();++i) {
		if (it->nbs[i]->rid==ospf->rid) {
			nb = it->nbs[i];
			break;
		}
	}
	puts("doing hello");
	if (nb==NULL) {
		nb = (neib*)malloc(sizeof(neib));
		nb->rid = ospf->rid;
		nb->ip = src;
		nb->s = S_DOWN;
		nb->dd_cnt = 0;
		nb->pri = *rtrpri;
		it->nbs.push_back(nb);
		puts("new neib");
	}
	nb->inac_cnt = 0;
	it->dr = *dr;
	it->bdr = *bdr;
	// trans(nb, E_HELLO);
	if (nb->s==S_DOWN) puts("received hello, DOWN => INIT"), nb->s=S_INIT;
	bool flag=true;
	for (int i=0;i<nb_cnt;++i) 
		if (nbrs[i]==my_rid) {
			//trans(nb, E_2WAY);
			if (nb->s==S_INIT) puts("2WAY, INIT => 2WAY"), nb->s=S_2WAY;
			flag=false;
			break;
		}
	if (flag) //trans(nb,E_1WAY);
		if (nb->s==S_2WAY) puts("1WAY, 2WAY => INIT"), nb->s=S_INIT;
	if (*dr==src||*bdr==src) 
		if (nb->s==S_2WAY) puts("AdjOK, 2WAY => ExSTART"), nb->s=S_ExSTART;
	return 0;
}
int deal_dd(inter * it, OSPFPack * ospf, in_addr_t src) {

	return 0;
}
int deal_lsr(inter * it, OSPFPack * ospf, in_addr_t src) {

	return 0;
}
int deal_lsu(inter * it, OSPFPack * ospf, in_addr_t src) {

	return 0;
}
int deal_lsack(inter * it, OSPFPack * ospf, in_addr_t src) {

	return 0;
}
