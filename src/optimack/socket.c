
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hping2.h"
#include "globals.h"
#include "util.h"
#include "logging.h"

void send_SYN(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    unsigned char* bytes = opts.bytes;
    /* Maximum segment size*/
    bytes[0] = 2;
    bytes[1] = 4;
    bytes[2] = 5;
    bytes[3] = 0xb4;
    /*Window scale: 7*/
    bytes[4] = 1;
    bytes[5] = 3;
    bytes[6] = 3;
    bytes[7] = 7;
    opts.size = 8;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}


void send_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}


void send_request(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}


void send_FIN_ACK(char *payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_FIN | TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

unsigned int wait_SYN_ACK(unsigned int ack = 0, int timeout = 1, unsigned short local_port = 8000, char* pkt_data = pkt_data)
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_SYN|TH_ACK;
    size_t pkt_len;
    int succ = -1;
    timespec _start, _end;
    clock_gettime(CLOCK_REALTIME, &_start);
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        // log_exp("wait SYNACK: succ %d, ack %d, recv_ack %d\n", succ, ack, recv_ack);

        if(ack != 0 && recv_ack != ack) succ = -1;
        //if(succ != 0) printf("failed to get seq\n");
        clock_gettime(CLOCK_REALTIME, &_end);
        int sec = diff(_end, _start).tv_sec;
        if (sec >= timeout) {
            break;
        }
    }
    while(succ != 0);

    //printf("seq from SYN-ACK: %u\n", recv_seq);
    return recv_seq;
}

unsigned int wait_data(unsigned int ack = 0, unsigned int seq = 1, unsigned short local_port = 8000, char* pkt_data = pkt_data)
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_ACK;
    size_t pkt_len;

    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        if(ack != 0 && recv_ack != ack) succ = -1;
        if(seq != 1 && recv_seq != seq) succ = -1;
        if(pkt_len == 0) succ = -1;
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    printf("seq from data: %u\n", recv_seq);
    return pkt_len;
}




void regular_tcp_fastopen_send(char* payload, int len)
{
    struct sockaddr_in servaddr;
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=inet_addr(remote_ip);
    servaddr.sin_port=htons(remote_port);

    /* create the socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    /* connect and send out some data */
    sendto(fd, payload, len, MSG_FASTOPEN, (struct sockaddr *)&servaddr, sizeof(servaddr));
}



void raw_tcp_fastopen_cookie(char* payload, unsigned int seq = 0)
{
    u_char bytes[12] = {0xfe,0x0c,0xf9,0x89,0xe6,0xdc,0x1f,0x66,0x8a,0xea,0x7f,0x9c};
    struct tcphdr_opts opts;
    memcpy(opts.bytes, bytes, 12);
    opts.size = 12;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN;
    header.th_seq = seq;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}


void raw_tcp_fastopen_req(char* payload, unsigned int seq = 0)
{
    struct tcphdr_opts opts;
    opts.bytes[0] = 0xfe;
    opts.bytes[1] = 0x04;
    opts.bytes[2] = 0xf9;
    opts.bytes[3] = 0x89;
    opts.size = 4;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN;
    header.th_seq = seq;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}




void send_fake_SYN(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_spoofed_SYN(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, fake_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_SYN_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN|TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_spoofed_SYN_ACK(char *sip, char *dip, unsigned short sport, unsigned short dport, char *payload, unsigned int ack, unsigned int seq = 1)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_SYN|TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(sport, dport, &header, &opts, sip, dip, 1, NULL, (u_char*)payload, strlen(payload), 1);
}



void send_spoofed_ACK(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, fake_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}




void send_spoofed_request(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, fake_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_RST(char* payload, unsigned int seq = 1, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_RST;
    header.th_seq = seq;
    header.th_ack = 0;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_wrongcsum_RST(char* payload, unsigned int seq = 1)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_RST;
    header.th_seq = seq;
    header.th_ack = 0;

    send_tcp3(local_port, remote_port, &header, &opts, local_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}


void send_RST_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_RST | TH_ACK;
    header.th_seq = seq;
    header.th_ack = ack;


    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_RST_with_MD5(char *payload, unsigned int seq = 1)
{
    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    struct tcphdr_opts opts;
    memcpy(opts.bytes, bytes, 20);
    opts.size = 20;

    struct tcphdr_bsd header;
    header.th_flags = TH_RST;
    header.th_seq = seq;
    header.th_ack = 0;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, 128, NULL, (u_char*)payload, strlen(payload), 1);
}

void send_FIN(char *payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128)
{
    struct tcphdr_opts opts;
    opts.size = 0;

    struct tcphdr_bsd header;
    header.th_flags = TH_FIN;
    header.th_seq = seq;
    header.th_ack = ack;
    header.th_win = 29200;

    send_tcp(local_port, remote_port, &header, &opts, local_ip, remote_ip, ttl, NULL, (u_char*)payload, strlen(payload), 1);
}

unsigned int wait_SYN()
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_SYN;
    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    //printf("seq from SYN: %u\n", recv_seq);
    return recv_seq;
}



unsigned int wait_ACK(unsigned int ack = 0)
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_ACK;
    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        if(ack != 0 && recv_ack != ack) succ = -1;
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    //printf("seq from ACK: %u\n", recv_seq);
    return recv_seq;
}

unsigned int wait_FIN()
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_FIN;
    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    //printf("seq from FIN: %u\n", recv_seq);
    return recv_seq;
}

unsigned int wait_FIN_ACK()
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_FIN | TH_ACK;
    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    //printf("seq from FIN-ACK: %u\n", recv_seq);
    return recv_seq;
}

unsigned int wait_RST()
{
    unsigned int recv_seq = 0, recv_ack = 0;
    unsigned char tcp_flags = TH_RST;
    int succ = -1;
    do{
        succ = wait_packet(local_ip, local_port, remote_ip, remote_port, tcp_flags, pkt_data, &pkt_len, &recv_seq, &recv_ack);
        //if(succ != 0) printf("failed to get seq\n");
    }
    while(succ != 0);

    //printf("seq from FIN-ACK: %u\n", recv_seq);
    return recv_seq;
}

void send_a_half_req(char *payload, unsigned int ack, unsigned int seq)
{
    local_port = rand() % 20000 + 30000; // generate random port (30000-39999)
    unsigned int client_ISN;
    //client_ISN = 345678;
    client_ISN = rand();

    // normal SYN request
    send_SYN("", 0, client_ISN);
    
    seq = wait_SYN_ACK();

    send_ACK("", seq+1, client_ISN + 1);
    send_request(payload, seq+1, client_ISN + 1);
}

void send_request_seg(char *payload, unsigned int ack, unsigned int seq, unsigned int len)
{
    assert(len < 100);
    char tmp[1000];
    for (int i=0; i<strlen(payload); i+=len) {
        strncpy(tmp, payload+i, len);
        send_request(tmp, ack, seq);
        seq+=len;
    }
}

void send_request2(char *payload, unsigned int ack, unsigned int seq)
{
    char tmp[10];
    for (int i=0; i<strlen(payload); i+=2) {
        tmp[0] = payload[i];
        tmp[1] = payload[i];
        tmp[1] = 0;
        send_request(tmp, ack, seq);
        seq++;
    }
}

