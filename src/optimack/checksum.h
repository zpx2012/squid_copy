#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <cstdint>
#include <arpa/inet.h>

uint16_t i4_sum_calc(uint16_t nwords, uint16_t* buf);
uint16_t  tcp_sum_calc(
	uint16_t len_tcp, 
	uint16_t *src_addr, 
	uint16_t *dst_addr, 
	uint16_t *buf);
void compute_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk);

#endif
