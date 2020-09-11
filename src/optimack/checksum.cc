#include "checksum.h"


//++++++++++++++++++++++++++++++++++++++++++++++++
//New IPv4 header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t i4_sum_calc(uint16_t nwords, uint16_t* buf) {
	//buffer present checksum
	uint16_t sum_buf = ( *(buf+5) );

	//set pointer to checksum on packet
	uint16_t *pt_sum =  buf+5;

	//set packet checksum to zero in order to compute checksum
	*pt_sum = htons(0);

	//initialize sum to zero
	uint32_t sum = 0;

	//sum it all up	
	int i;
	for (i=0; i<nwords; i++)
		sum += *(buf+i);
	
	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while(sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	//take the one's copliement of sum
	sum = ~sum;

	//reinstall original i4sum_buf
	*pt_sum = (uint16_t) (sum_buf);

	//reinstate prior value
	( *(buf+5) ) = sum_buf;

	return sum;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//New TCP header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t  tcp_sum_calc(
	uint16_t len_tcp, 
	uint16_t *src_addr, 
	uint16_t *dst_addr, 
	uint16_t *buf) {

	//buffer checksum
	uint16_t old_sum = buf[8];//checksum

	//pointer to tcp sum
	uint16_t *pt_sum = buf+8;

	//replace checksum with 0000
	*pt_sum = 0;

	uint16_t prot_tcp = 6;
	uint16_t padd = 0;
	uint32_t sum;

	//Find out if the length of data is even or odd number. If odd,
	//add a padding byte = 0 at the end of packet
	if( (len_tcp & 1) == 1) {
		padd = 1;
		buf[ (len_tcp-1)>>1 ] &= 0x00FF;
	}

	//initialize sum to zero
	sum = 0;

	//make 16 bit words out of every two adjacent 8 bit words and
	//calculate the sum of all 16 bit words
	int i;
	for (i=0; i<((len_tcp+padd)>>1); i++)
		sum +=  (*(buf + i));


	//add the TCP pseudo header which contains
	//the ip srouce and ip destination addresses
	sum +=  (*src_addr);
	sum +=  (*(src_addr + 1));
	sum +=  (*dst_addr);
	sum +=  (*(dst_addr + 1));

	//the protocol number and the length of the TCP packet
	sum += htons(prot_tcp);
	sum += htons(len_tcp);

	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while (sum>>16) sum = (sum & 0xFFFF) + (sum >> 16);


	//reinstate buffered checksum
	*pt_sum = old_sum;

	return (uint16_t) sum;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//compute checksums: computes i4 & TCP checksums for new packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
void compute_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk) {

	//create 16-bit word pointer
	uint16_t *pt_buf16 = (uint16_t *) (buf);	

	//set checksum to 0
	//*(pt_buf16 + 5) = 0;

	//update len_pk in IPv4 header
	*(pt_buf16+1) = (uint16_t) htons(lenpk);	
	

	//update i4 checksum
	uint16_t i4sum = i4_sum_calc( (leni4>>1), pt_buf16);

	//enter fixed i4 checksum into packet
	*(pt_buf16 + 5) = i4sum;

	//compute checksum. Note: Totlen may have changed during manipulation. It is therefore updated.
	//delta method
	*(pt_buf16 + (leni4>>1) + 8) = 0;
	uint16_t new_tcp_header_checksum = tcp_sum_calc(lenpk-leni4, pt_buf16+6, pt_buf16+8, (uint16_t *) (buf + leni4));


	*(pt_buf16 + (leni4>>1) + 8) = ~( (uint16_t)(new_tcp_header_checksum));
}