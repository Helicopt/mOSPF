#include "common.h"
#include <bits/stdc++.h>

int gen_hello(OSPFPack * ospf, inter * it);

int gen_dd(OSPFPack * ospf, inter * it);

int gen_lsr(OSPFPack * ospf, inter * it);

int gen_lsu(OSPFPack * ospf, inter * it);

int gen_lsack(OSPFPack * ospf, inter * it);


int deal_hello(inter * it, OSPFPack * ospf, in_addr_t src);

int deal_dd(inter * it, OSPFPack * ospf, in_addr_t src);

int deal_lsr(inter * it, OSPFPack * ospf, in_addr_t src);

int deal_lsu(inter * it, OSPFPack * ospf, in_addr_t src);

int deal_lsack(inter * it, OSPFPack * ospf, in_addr_t src);

