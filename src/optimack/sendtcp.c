/* 
 * $smu-mark$ 
 * $name: sendtcp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include "hping2.h"


void hex_dump(void *packet, int size)
{
	unsigned char *byte = (unsigned char*)packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) ((unsigned char*)packet+size); byte++) {
		count++;
		printf("%02x", *byte);
		if (count % 2 == 0) printf(" ");
		if (count % 16 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}


void create_tcp_timestamp_option(struct tcphdr_opts* tcp_opts, unsigned int timestamp)
{
	unsigned char* tstamp = tcp_opts->bytes;
	/* tcp timestamp option */
	tstamp[0] = tstamp[1] = 1; /* NOOP */
	tstamp[2] = 8;
	tstamp[3] = 10; /* 10 bytes, kind+len+T1+T2 */

	// delibrately old timestamp, the value is a random one
	memcpy(tstamp+4, &timestamp, 4);

	// delibrately old timestamp
/*	tstamp[4] = 0x54;
	tstamp[5] = 0xa2;
	tstamp[6] = 0x98;
	tstamp[7] = 0x3e;
	*/
	memset(tstamp+8, 0, 4); /* zero */
	tcp_opts->size = 12;
}


// with tcp options allowed
void send_tcp(int sport, int dport, struct tcphdr_bsd* tcp_in, struct tcphdr_opts* tcp_opts, const char* srcIP, const char* dstIP, int ttl, struct myiphdr* ip_in, const u_char *payload, int payload_size, int count)
{
	int			packet_size;
	char			*packet, *data;
	//	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
//	unsigned char		*tstamp;
	unsigned char		*tcp_option_bytes;

	int tcp_opt_size = 0;
	if(tcp_opts != NULL)
	{
		tcp_opt_size = tcp_opts->size;
	}

	packet_size = TCPHDR_SIZE + tcp_opt_size + payload_size;
	packet = (char*)malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	struct mytcphdr* tcp =  (struct mytcphdr*) (packet+PSEUDOHDR_SIZE);
	//	tstamp = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	tcp_option_bytes = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE+tcp_opt_size);

	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	inet_pton(AF_INET, srcIP, &pseudoheader->saddr);
	inet_pton(AF_INET, dstIP, &pseudoheader->daddr);

	/* tcp pseudo header */
	//	memcpy(&pseudoheader->saddr, &local.sin_addr.s_addr, 4);
	//	memcpy(&pseudoheader->daddr, &remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 6; /* tcp */
	pseudoheader->length		= htons(TCPHDR_SIZE+tcp_opt_size+payload_size);

	/* tcp header */
	tcp->th_dport	= htons(dport);
	tcp->th_sport	= htons(sport);

	/* sequence number and ack are random if not set */
	tcp->th_seq = htonl(tcp_in->th_seq);
	tcp->th_ack = htonl(tcp_in->th_ack);

	if(tcp_option_bytes != NULL)
		memcpy(tcp_option_bytes, tcp_opts->bytes, tcp_opts->size);

	tcp->th_off	= ((TCPHDR_SIZE + tcp_opt_size) >> 2);
	tcp->th_win	= htons(tcp_in->th_win);
	tcp->th_flags	= tcp_in->th_flags;

	/* data */
	//	data_handler(data, payload, payload_size);
	memcpy(data, payload, payload_size);

    //hex_dump(packet, PSEUDOHDR_SIZE + packet_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, PSEUDOHDR_SIZE +
			packet_size);
#endif

	/* adds this pkt in delaytable */
	//	delaytable_add(sequence, src_port, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(0, ttl, (char*)srcIP, (char*)dstIP, packet+PSEUDOHDR_SIZE, 
			packet_size);
	free(packet);
}

// with tcp options allowed
void send_tcp2(int sport, int dport, struct tcphdr_bsd* tcp_in, struct tcphdr_opts* tcp_opts, const char* srcIP, const char* dstIP, int ttl, struct myiphdr* ip_in, const u_char *payload, int payload_size, int count)
{
	int			packet_size;
	char			*packet, *data;
	//	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
//	unsigned char		*tstamp;
	unsigned char		*tcp_option_bytes;

	int tcp_opt_size = 0;
	if(tcp_opts != NULL)
	{
		tcp_opt_size = tcp_opts->size;
	}

	packet_size = TCPHDR_SIZE + tcp_opt_size + payload_size;
	packet = (char*)malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	struct mytcphdr* tcp =  (struct mytcphdr*) (packet+PSEUDOHDR_SIZE);
	//	tstamp = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	tcp_option_bytes = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE+tcp_opt_size);

	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	inet_pton(AF_INET, srcIP, &pseudoheader->saddr);
	inet_pton(AF_INET, dstIP, &pseudoheader->daddr);

	/* tcp pseudo header */
	//	memcpy(&pseudoheader->saddr, &local.sin_addr.s_addr, 4);
	//	memcpy(&pseudoheader->daddr, &remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 6; /* tcp */
	pseudoheader->length		= htons(TCPHDR_SIZE+tcp_opt_size+payload_size);

	/* tcp header */
	tcp->th_dport	= htons(dport);
	tcp->th_sport	= htons(sport);

	/* sequence number and ack are random if not set */
	tcp->th_seq = htonl(tcp_in->th_seq);
	tcp->th_ack = htonl(tcp_in->th_ack);

	if(tcp_option_bytes != NULL)
		memcpy(tcp_option_bytes, tcp_opts->bytes, tcp_opts->size);

	tcp->th_off	= ((TCPHDR_SIZE + tcp_opt_size) >> 2) ;
	//tcp->th_off	= 15;
	tcp->th_win	= htons(tcp_in->th_win);
	tcp->th_flags	= tcp_in->th_flags;

	/* data */
	//	data_handler(data, payload, payload_size);
	memcpy(data, payload, payload_size);

    //hex_dump(packet, PSEUDOHDR_SIZE + packet_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, PSEUDOHDR_SIZE +
			packet_size);
#endif
        tcp->th_sum = 1234;

	/* adds this pkt in delaytable */
	//	delaytable_add(sequence, src_port, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(0, ttl, (char*)srcIP, (char*)dstIP, packet+PSEUDOHDR_SIZE, 
			packet_size);
	free(packet);
}


// send wrong checksum packets
void send_tcp3(int sport, int dport, struct tcphdr_bsd* tcp_in, struct tcphdr_opts* tcp_opts, const char* srcIP, const char* dstIP, int ttl, struct myiphdr* ip_in, const u_char *payload, int payload_size, int count)
{
	int			packet_size;
	char			*packet, *data;
	//	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
//	unsigned char		*tstamp;
	unsigned char		*tcp_option_bytes;

	int tcp_opt_size = 0;
	if(tcp_opts != NULL)
	{
		tcp_opt_size = tcp_opts->size;
	}

	packet_size = TCPHDR_SIZE + tcp_opt_size + payload_size;
	packet = (char*)malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	struct mytcphdr* tcp =  (struct mytcphdr*) (packet+PSEUDOHDR_SIZE);
	//	tstamp = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	tcp_option_bytes = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE+tcp_opt_size);

	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	inet_pton(AF_INET, srcIP, &pseudoheader->saddr);
	inet_pton(AF_INET, dstIP, &pseudoheader->daddr);

	/* tcp pseudo header */
	//	memcpy(&pseudoheader->saddr, &local.sin_addr.s_addr, 4);
	//	memcpy(&pseudoheader->daddr, &remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 6; /* tcp */
	pseudoheader->length		= htons(TCPHDR_SIZE+tcp_opt_size+payload_size);

	/* tcp header */
	tcp->th_dport	= htons(dport);
	tcp->th_sport	= htons(sport);

	/* sequence number and ack are random if not set */
	tcp->th_seq = htonl(tcp_in->th_seq);
	tcp->th_ack = htonl(tcp_in->th_ack);

	if(tcp_option_bytes != NULL)
		memcpy(tcp_option_bytes, tcp_opts->bytes, tcp_opts->size);

	tcp->th_off	= ((TCPHDR_SIZE + tcp_opt_size) >> 2) ;
	//tcp->th_off = tcp_in->th_off;
	tcp->th_win = htons(tcp_in->th_win);
	tcp->th_flags = tcp_in->th_flags;

	/* data */
	//	data_handler(data, payload, payload_size);
	memcpy(data, payload, payload_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, PSEUDOHDR_SIZE +
			packet_size);
#endif
    tcp->th_sum = 1234;

	/* adds this pkt in delaytable */
	//	delaytable_add(sequence, src_port, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(0, ttl, (char*)srcIP, (char*)dstIP, packet+PSEUDOHDR_SIZE, 
			packet_size);
	free(packet);
}

// with tcp options allowed (set ip header option Strict Source Route)
void send_tcp_ssr(int sport, int dport, struct tcphdr_bsd* tcp_in, struct tcphdr_opts* tcp_opts, const char* srcIP, const char* dstIP, int ttl, struct myiphdr* ip_in, const u_char *payload, int payload_size, int count)
{
	int			packet_size;
	char			*packet, *data;
	//	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
//	unsigned char		*tstamp;
	unsigned char		*tcp_option_bytes;

	int tcp_opt_size = 0;
	if(tcp_opts != NULL)
	{
		tcp_opt_size = tcp_opts->size;
	}

	packet_size = TCPHDR_SIZE + tcp_opt_size + payload_size;
	packet = (char*)malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	struct mytcphdr* tcp =  (struct mytcphdr*) (packet+PSEUDOHDR_SIZE);
	//	tstamp = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	tcp_option_bytes = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE+tcp_opt_size);

	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	inet_pton(AF_INET, srcIP, &pseudoheader->saddr);
	inet_pton(AF_INET, dstIP, &pseudoheader->daddr);

	/* tcp pseudo header */
	//	memcpy(&pseudoheader->saddr, &local.sin_addr.s_addr, 4);
	//	memcpy(&pseudoheader->daddr, &remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 6; /* tcp */
	pseudoheader->length		= htons(TCPHDR_SIZE+tcp_opt_size+payload_size);

	/* tcp header */
	tcp->th_dport	= htons(dport);
	tcp->th_sport	= htons(sport);

	/* sequence number and ack are random if not set */
	tcp->th_seq = htonl(tcp_in->th_seq);
	tcp->th_ack = htonl(tcp_in->th_ack);

	if(tcp_option_bytes != NULL)
		memcpy(tcp_option_bytes, tcp_opts->bytes, tcp_opts->size);

	tcp->th_off	= ((TCPHDR_SIZE + tcp_opt_size) >> 2) ;
	tcp->th_win	= htons(tcp_in->th_win);
	tcp->th_flags	= tcp_in->th_flags;

	/* data */
	//	data_handler(data, payload, payload_size);
	memcpy(data, payload, payload_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, PSEUDOHDR_SIZE +
			packet_size);
#endif

	/* adds this pkt in delaytable */
	//	delaytable_add(sequence, src_port, time(NULL), get_usec(), S_SENT);

        // set strict source route
        char* ip_opt;
        unsigned char ip_optlen;
        ip_opt = (char*)malloc(100);
        set_ip_ssr(ip_opt, &ip_optlen);

	/* send packet */
	send_ip(0, ttl, (char*)srcIP, (char*)dstIP, packet+PSEUDOHDR_SIZE, 
                packet_size, 0, 0, ip_opt, ip_optlen);

        free(ip_opt);
	free(packet);
}

void set_ip_ssr(char *ip_opt, unsigned char *ip_optlen)
{
    ip_opt[0] = 137;
    ip_opt[1] = 20;
    ip_opt[2] = 4;

    inet_pton(AF_INET, "169.235.25.185", ip_opt+3);
    *ip_optlen = 20;

}

