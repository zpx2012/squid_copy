/* waitpacket.c -- handle and print the incoming packet
 * Copyright(C) 1999-2001 Salvatore Sanfilippo
 * Under GPL, see the COPYING file for more information about
 * the license. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

#include "hping2.h"
#include "util.h"
#include "logging.h"

static int icmp_unreach_rtt(void *quoted_ip, int size,
		int *seqp, float *ms_delay);
static void print_tcp_timestamp(void *tcp, int tcpsize);
static int recv_icmp(struct myiphdr, void *packet, size_t size, char*, char*);
static int recv_udp(void *packet, size_t size);
static long long recv_tcp(void *packet, size_t size, int dst_port, struct tcphdr_bsd*);
static void hex_dump(void *packet, int size);
static void human_dump(void *packet, int size);
//static void handle_hcmp(char *packet, int size);

//static struct myiphdr ip;
//static int ip_size;
//static struct in_addr src, dst;


int cmp_ip(const char* ip_str, u_int32_t ip_inaddr){
	// struct sockaddr_in sockaddr;
    // sockaddr.sin_family = AF_INET;
    // store this IP address in struct sockaddr_in:
	// in_addr_t in_addr = inet_addr(ip_str);
    // inet_pton(AF_INET, ip_str, &(sockaddr.sin_addr));
	return inet_addr(ip_str) == ip_inaddr;
	
	// return memcmp(ip_inaddr, &sockaddr.sin_addr, sizeof(sockaddr.sin_addr));
}


int wait_packet(const char* local_ip, unsigned short local_port, const char* remote_ip, unsigned short remote_port, unsigned char tcp_flags, char* pkt_data, size_t *pkt_len, unsigned int *seq, unsigned int *ack)
{
    int size, iphdr_size, tcphdr_size, enc_size;
    char packet[IP_MAX_SIZE];
    char *ip_packet, *enc_packet;

    size = read_packet(packet, IP_MAX_SIZE);
    switch(size) {
        case 0:
            printf("size == 0\n");
            return -1;
        case -1:
            printf("size == -1\n");
            exit(1);
    }

    //printf("size: %d\n", size);
    //hex_dump(packet, size);

    /* IP packet pointer and len */
    ip_packet = packet;
    unsigned int ip_size = size;

//  printf("ip size: %d\n", ip_size);
    /* Truncated IP header? */
    if (ip_size < IPHDR_SIZE) {
        if (opt_debug)
            printf("[|ip fix]\n");
        return -1;
    }

    struct myiphdr ip;
    memcpy(&ip, packet, sizeof(ip));
    iphdr_size = ip.ihl * 4;

    /* Bad IP header len? */
    if (iphdr_size > ip_size) {
        if (opt_debug)
            printf("[|iphdr size]\n");
        return -1;
    }
    /* Handle the HCMP for almost safe file transfer with hping */
    //if (opt_sign)
    //	handle_hcmp(ip_packet, ip_size);
    
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    local_addr.sin_family = AF_INET;
    remote_addr.sin_family = AF_INET;
    // store this IP address in struct sockaddr_in:
    inet_pton(AF_INET, local_ip, &(local_addr.sin_addr));
    inet_pton(AF_INET, remote_ip, &(remote_addr.sin_addr));

//    char temp[INET_ADDRSTRLEN+1];
//    inet_ntop(AF_INET, &(ip.saddr), temp, INET_ADDRSTRLEN);
//    char temp2[INET_ADDRSTRLEN+1];
//    inet_ntop(AF_INET, &(ip.daddr), temp2, INET_ADDRSTRLEN);
//    printf("src IP: %s\n", temp);
//    printf("dest IP: %s\n", temp2);
//    printf("local IP: %s\n", local_ip);
	
    /* Check if the dest IP address is the one of our interface */
    if (memcmp(&ip.daddr, &local_addr.sin_addr, sizeof(ip.daddr)))
    {
     	log_exp("wait packet: destination IP does not match\n");
        return -1;
    }
    if (memcmp(&ip.saddr, &remote_addr.sin_addr, sizeof(ip.saddr)))
    {
     	log_exp("wait packet: source IP does not match\n");
        return -1;
    }

    /* Get the encapsulated protocol offset and size */
    enc_packet = ip_packet + iphdr_size;
    enc_size = ip_size - iphdr_size;
    memcpy(pkt_data, enc_packet, enc_size);
    *pkt_len = enc_size;

    switch(ip.protocol) {
        case IPPROTO_ICMP:
            //match = recv_icmp(ip, enc_packet, enc_size, localIP, remoteIP);
            return -1;
        case IPPROTO_UDP:
            //match = recv_udp(enc_packet, enc_size);
            return -1;
        case IPPROTO_TCP:
            if (size < TCPHDR_SIZE) {
                printf("[|tcp]\n");
                return -1;
            }
            struct mytcphdr tcp;
            memcpy(&tcp, enc_packet, sizeof(tcp));
            tcphdr_size = tcp.th_off * 4;

            unsigned short src_port, dst_port;
            src_port = htons(tcp.th_sport);
            dst_port = htons(tcp.th_dport);
            //printf("src Port: %d\n", src_port);
            //printf("dest Port: %d\n", dst_port);
            //printf("TCP flags: %s\n", tcp_flags_str(tcp.th_flags));

            if (dst_port != local_port && local_port != 0) 
            {
                log_exp("wait packet: destination port does not match. recv: %d, wanting: %d\n", dst_port, local_port);
                return -1;
            }
            if (src_port != remote_port && remote_port != 0) 
            {
                log_exp("wait packet: source port does not match. recv: %d, wanting: %d\n", src_port, remote_port);
                return -1;
            }
            //printf("src Port: %d\n", src_port);
            //printf("dest Port: %d\n", dst_port);
            //printf("TCP flags: %s\n", tcp_flags_str(tcp.th_flags));
            if (tcp.th_flags != tcp_flags)
            {
                log_exp("wait packet: tcp flags does not match. recv: %d, wanting: %d\n", tcp.th_flags, tcp_flags);
                return -1;
            }
            enc_packet = ip_packet + iphdr_size + tcphdr_size;
            enc_size = ip_size - iphdr_size - tcphdr_size;
            memcpy(pkt_data, enc_packet, enc_size);
            *pkt_len = enc_size;
            *seq = htonl(tcp.th_seq);
            *ack = htonl(tcp.th_ack);
            return 0;
        default:
            return -1;
    }

    return 0;
}


int wait_rst_packet_ipid(const char* localIP, const char* remoteIP, int dst_port)
{
	//    printf("in wait_packet()\n");
	int match = 0;
	long long seq = -1;
	linkhdr_size = 14;
        int size, iphdr_size, enc_size;
	char packet [IP_MAX_SIZE+linkhdr_size];
	char *ip_packet, *enc_packet;

	//    opt_debug = 1;

//	    printf("max size: %d\n", IP_MAX_SIZE + linkhdr_size);
	size = read_packet(packet, IP_MAX_SIZE+linkhdr_size);
	switch(size) {
		case 0:
			printf("size == 0\n");
			return -1;
		case -1:
			printf("size == -1\n");
			exit(1);
	}


    int i;
//	    printf("size: %d\n", size);
	for(i = 0; i < size; ++i)
	{
		//        printf("%x ", (u_char)packet[i]);
	}
	/* Check if the packet is shorter than the link header size */
	if (size < linkhdr_size) {
		if (opt_debug)
			printf("DEBUG: WARNING: packet size < linkhdr_size\n");
		return -1;
	}

	/* IP packet pointer and len */
	ip_packet = packet;
	int ip_size = size;

//	printf("ip size: %d\n", ip_size);
	/* Truncated IP header? */
	if (ip_size < IPHDR_SIZE) {
		if (opt_debug)
			printf("[|ip fix]\n");
		return -1;
	}

	struct myiphdr ip;
	memcpy(&ip, packet, sizeof(ip));
	iphdr_size = ip.ihl * 4;

	/* Bad IP header len? */
	if (iphdr_size > ip_size) {
		if (opt_debug)
			printf("[|iphdr size]\n");
		return -1;
	}
//	printf("444444444444\n");

	/* Handle the HCMP for almost safe file transfer with hping */
	//if (opt_sign)
	//	handle_hcmp(ip_packet, ip_size);

	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddr;
	localAddr.sin_family = AF_INET;
	remoteAddr.sin_family = AF_INET;
	// store this IP address in struct sockaddr_in:
	inet_pton(AF_INET, localIP, &(localAddr.sin_addr));
	inet_pton(AF_INET, remoteIP, &(remoteAddr.sin_addr));


	char temp[INET_ADDRSTRLEN+1];
	inet_ntop(AF_INET, &(ip.daddr), temp, INET_ADDRSTRLEN);
	char temp2[INET_ADDRSTRLEN+1];
	inet_ntop(AF_INET, &(ip.saddr), temp2, INET_ADDRSTRLEN);
//	printf("dest IP: %s\n", temp);
//	printf("src IP: %s\n", temp2);
//	printf("local IP: %s\n", localIP);
	
	/* Check if the dest IP address is the one of our interface */
	if (memcmp(&ip.daddr, &localAddr.sin_addr, sizeof(ip.daddr)))
	{
//		printf("destination IP does not match\n");
		return -1;
	}
	/* If the packet isn't an ICMP error it should come from
	 * our target IP addresss. We accepts packets from all the
	 * source if the random destination option is active */
	if (ip.protocol != IPPROTO_ICMP) {
		if (memcmp(&ip.saddr, &remoteAddr.sin_addr, sizeof(ip.saddr)))
		{
//			printf("source IP does not match\n");
			return -1;
		}
	}

	/* Get the encapsulated protocol offset and size */
	enc_packet = ip_packet + iphdr_size;
	enc_size = ip_size - iphdr_size;

	/* Put the IP source and dest addresses in a struct in_addr */
	//	memcpy(&src, &(ip.saddr), sizeof(struct in_addr));
	//	memcpy(&dst, &(ip.daddr), sizeof(struct in_addr));
	struct tcphdr_bsd tcp;
	tcp.th_flags = TH_RST;
	int ipid = -1;
//	printf("ip protocol\n"); 
	switch(ip.protocol) {
		case IPPROTO_ICMP:
			//		match = recv_icmp(ip, enc_packet, enc_size, localIP, remoteIP);
			break;
		case IPPROTO_UDP:
			//		match = recv_udp(enc_packet, enc_size);
			break;
		case IPPROTO_TCP:
			seq = recv_tcp(enc_packet, enc_size, dst_port, &tcp);
            
			if(seq != -1)
			{
				ipid = ntohs(ip.id);
			}
			break;
		default:
			return -1;
	}

	if (match)
		recv_pkt++;

	// should return the port number instead
	return ipid;
}






int wait_packet_ipid(const char* localIP, const char* remoteIP, int dst_port)
{
	//    printf("in wait_packet()\n");
	int match = 0;
	long long seq = -1;
	linkhdr_size = 14;
	int size;
	unsigned int iphdr_size, enc_size;
	char packet [IP_MAX_SIZE+linkhdr_size];
	char *ip_packet, *enc_packet;

	//    opt_debug = 1;

//	    printf("max size: %d\n", IP_MAX_SIZE + linkhdr_size);
	size = read_packet(packet, IP_MAX_SIZE+linkhdr_size);
	switch(size) {
		case 0:
			printf("size == 0\n");
			return -1;
		case -1:
			printf("size == -1\n");
			exit(1);
	}

    int i;
//	    printf("size: %d\n", size);
	for(i = 0; i < size; ++i)
	{
		//        printf("%x ", (u_char)packet[i]);
	}
	/* Check if the packet is shorter than the link header size */
	if (size < linkhdr_size) {
		if (opt_debug)
			printf("DEBUG: WARNING: packet size < linkhdr_size\n");
		return -1;
	}

	/* IP packet pointer and len */
	ip_packet = packet;
	int ip_size = size;

//	printf("ip size: %d\n", ip_size);
	/* Truncated IP header? */
	if (ip_size < IPHDR_SIZE) {
		if (opt_debug)
			printf("[|ip fix]\n");
		return -1;
	}

	struct myiphdr ip;
	memcpy(&ip, packet, sizeof(ip));
	iphdr_size = ip.ihl * 4;

	/* Bad IP header len? */
	if (iphdr_size > ip_size) {
		if (opt_debug)
			printf("[|iphdr size]\n");
		return -1;
	}
//	printf("444444444444\n");

	/* Handle the HCMP for almost safe file transfer with hping */
	//if (opt_sign)
	//	handle_hcmp(ip_packet, ip_size);

	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddr;
	localAddr.sin_family = AF_INET;
	remoteAddr.sin_family = AF_INET;
	// store this IP address in struct sockaddr_in:
	inet_pton(AF_INET, localIP, &(localAddr.sin_addr));
	inet_pton(AF_INET, remoteIP, &(remoteAddr.sin_addr));


	char temp[INET_ADDRSTRLEN+1];
	inet_ntop(AF_INET, &(ip.daddr), temp, INET_ADDRSTRLEN);
	char temp2[INET_ADDRSTRLEN+1];
	inet_ntop(AF_INET, &(ip.saddr), temp2, INET_ADDRSTRLEN);
//	printf("dest IP: %s\n", temp);
//	printf("src IP: %s\n", temp2);
//	printf("local IP: %s\n", localIP);
	
	/* Check if the dest IP address is the one of our interface */
	if (memcmp(&ip.daddr, &localAddr.sin_addr, sizeof(ip.daddr)))
	{
//		printf("destination IP does not match\n");
		return -1;
	}
	/* If the packet isn't an ICMP error it should come from
	 * our target IP addresss. We accepts packets from all the
	 * source if the random destination option is active */
	if (ip.protocol != IPPROTO_ICMP) {
		if (memcmp(&ip.saddr, &remoteAddr.sin_addr, sizeof(ip.saddr)))
		{
//			printf("source IP does not match\n");
			return -1;
		}
	}

	/* Get the encapsulated protocol offset and size */
	enc_packet = ip_packet + iphdr_size;
	enc_size = ip_size - iphdr_size;

	/* Put the IP source and dest addresses in a struct in_addr */
	//	memcpy(&src, &(ip.saddr), sizeof(struct in_addr));
	//	memcpy(&dst, &(ip.daddr), sizeof(struct in_addr));
	struct tcphdr_bsd tcp;
	tcp.th_flags = TH_ACK;
	int ipid = -1;
//	printf("ip protocol\n"); 
	switch(ip.protocol) {
		case IPPROTO_ICMP:
			//		match = recv_icmp(ip, enc_packet, enc_size, localIP, remoteIP);
			break;
		case IPPROTO_UDP:
			//		match = recv_udp(enc_packet, enc_size);
			break;
		case IPPROTO_TCP:
			seq = recv_tcp(enc_packet, enc_size, dst_port, &tcp);
			if(seq != -1)
			{
				ipid = ntohs(ip.id);
			}
			break;
		default:
			return -1;
	}

	if (match)
		recv_pkt++;

	// should return the port number instead
	return ipid;
}


int recv_udp(void *packet, size_t size)
{
	struct myudphdr udp;
	int sequence = 0, status;
	float ms_delay;

	if (size < UDPHDR_SIZE) {
		printf("[|udp]\n");
		return 0;
	}
	memcpy(&udp, packet, sizeof(udp));

	/* check if the packet matches */
	if ((ntohs(udp.uh_sport) == dst_port) ||
			(opt_force_incdport &&
			 (ntohs(udp.uh_sport) >= base_dst_port &&
			  ntohs(udp.uh_sport) <= dst_port)))
	{
		return 1;
	}
	return 0;
}

long long recv_tcp(void *packet, size_t size, int dst_port, struct tcphdr_bsd* tcp_match)
{
//		printf("in recv_tcp()\n");
	struct mytcphdr tcp;
	int sequence = 0, status;
	float ms_delay;
	char flags[16];

	if (size < TCPHDR_SIZE) {
		printf("[|tcp]\n");
		return 0;
	}
	memcpy(&tcp, packet, sizeof(tcp));

	char cmd[1000];
	//    perror("HPING *********************** entering recv_tcp():");

	//    sprintf(cmd, "HPING *********************** ntohs(tcp.th_dport): %d, dst_port: %d\n", ntohs(tcp.th_dport), dst_port);
	//    perror(cmd);
	//    printf("HPING *********************** ntohs(tcp.th_sport): %d, dst_port: %d\n", ntohs(tcp.th_sport), dst_port);
	/* check if the packet matches */
	if (ntohs(tcp.th_dport) == dst_port)
	{
		//        printf("HPING ************** packet matched!!!!!!!!!!!!!!\n");
		//        sprintf(cmd, "HPING ************** packet matched!!!!!!!!!!!!!!\n");
		if (tcp.th_flags != tcp_match->th_flags)
		{
			printf("packet not match\n");
			return 0;
		}

		//        printf("HPING ************* printing the response packet\n");
        printf("packet matched\n");
		long long seq = ntohl(tcp.th_seq);

		return seq;
	}
	return 0;
}


void print_tcp_timestamp(void *tcp, int tcpsize)
{
	int optlen;
	unsigned char *opt;
	__u32 tstamp, echo;
	static __u32 last_tstamp = 0;
	struct mytcphdr tmptcphdr;
	unsigned int tcphdrlen;

	if (tcpsize < TCPHDR_SIZE)
		return;
	memcpy(&tmptcphdr, tcp, sizeof(struct mytcphdr));
	tcphdrlen = tmptcphdr.th_off * 4;

	/* bad len or no options in the TCP header */
	if (tcphdrlen <= 20 || tcphdrlen < tcpsize)
		return;
	optlen = tcphdrlen - TCPHDR_SIZE; 
	opt = (unsigned char*)tcp + TCPHDR_SIZE; /* skips the TCP fix header */
	while(optlen) {
		switch(*opt) {
			case 0: /* end of option */
				return;
			case 1: /* noop */
				opt++;
				optlen--;
				continue;
			default:
				if (optlen < 2)
					return;
				if (opt[1] > optlen)
					return;
				if (opt[0] != 8) { /* not timestamp */
					optlen -= opt[1];
					opt += opt[1];
					continue;
				}
				/* timestamp found */
				if (opt[1] != 10) /* bad len */
					return;
				memcpy(&tstamp, opt+2, 4);
				memcpy(&echo, opt+6, 4);
				tstamp = ntohl(tstamp);
				echo = ntohl(echo);
				goto found;
		}
	}
found:
	printf("  TCP timestamp: tcpts=%u\n", tstamp);
	if (last_tstamp && !opt_waitinusec) {
		int tsdiff = (tstamp - last_tstamp) / sending_wait;
		int hz_set[] = { 2, 10, 100, 1000, 0 };
		int hzdiff = -1;
		int hz = 0, sec;
		int days, hours, minutes;
		if (tsdiff > 0) {
			int i = 0;
			while(hz_set[i]) {
				if (hzdiff == -1) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				} else if (hzdiff > ABS(tsdiff-hz_set[i])) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				}
				i++;
			}
			printf("  HZ seems hz=%d\n", hz);
			sec = tstamp/hz; /* Get the uptime in seconds */
			days = sec / (3600*24);
			sec %= 3600*24;
			hours = sec / 3600;
			sec %= 3600;
			minutes = sec / 60;
			sec %= 60;
			printf("  System uptime seems: %d days, %d hours, "
					"%d minutes, %d seconds\n",
					days, hours, minutes, sec);
		}
	}
	printf("\n");
	last_tstamp = tstamp;
}

/* This function is exported to listen.c also */
int read_packet(void *packet, int size)
{
	size = recv(sockpacket, packet, size, 0);
	//    printf("recv size: %d\n", size);
	if (size == -1) {
		if (errno != EINTR)
			perror("[wait_packet] recv");
		else
			return 0;
	}
	return size;
}

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

void human_dump(void *packet, int size)
{
	unsigned char *byte = (unsigned char*)packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) ((unsigned char*)packet+size); byte++) {
		count ++;
		if (isprint(*byte))
			printf("%c", *byte);
		else
			printf(".");
		if (count % 32 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}



