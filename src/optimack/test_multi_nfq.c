#include "hping2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

#include <iostream> 
#include <fstream>
#include <iterator>
#include <vector>
#include <set>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

// #include "logging.h"
// #include "util.h"
// #include "socket.h"

FILE* log;
void hex_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    fprintf(log, "\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count++;
        // printf("%02x ", *byte);
        fprintf(log, "%02x ", *byte);
        if (count % 16 == 0) fprintf(log, "\n\t\t");
    }
    fprintf(log, "\n\n");
}

void human_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    printf("\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count ++; 
        if (isprint(*byte))
            printf("%c", *byte);
        else
            printf(".");
        if (count % 32 == 0) printf("\n\t\t");
    }   
    printf("\n\n");
}

int lock = 0, add = 0, sub = 0;
long long counter = 0;
int count = 0;

int deposit(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data)
{
    if(lock > 0){
        printf("start deposit\n");
        int i;
        for(i=0;i<1e7;++i)
            ++counter;
        add++;
        printf("count %lld, add %d, sub %d\n", counter, add, sub);
    }
}

int withdraw(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data)
{
    printf("start withdraw\n");
    lock++;
    int i;
    for(i=0;i<1e7;++i)
        --counter;
    sub++;
    printf("count %lld, add %d, sub %d\n", counter, add, sub);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data);
void *nfq_loop(void *arg);

int nfq_stop;
struct nfq_loop_args{
    struct nfq_handle * nfq_h;
    int nfq_fd;
};

int setup_nfq(int NF_QUEUE_NUM)
{
    struct nfq_handle * g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        printf("error during nfq_open()\n");
        return -1;
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        return -1;
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        return -1;
    }

    // set up a queue
    printf("binding this socket to queue %d\n", NF_QUEUE_NUM);
    struct nfq_q_handle *g_nfq_qh;
    if(NF_QUEUE_NUM == 5)
        g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, NULL);
    else
        g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, NULL);

    if (!g_nfq_qh) {
        printf("error during nfq_create_queue()\n");
        return -1;
    }
    printf("nfq queue handler: %p\n", g_nfq_qh);

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        printf("can't set packet_copy mode\n");
        return -1;
    }

#define NFQLENGTH 1024*200
#define BUFLENGTH 4096
    if (nfq_set_queue_maxlen(g_nfq_qh, NFQLENGTH) < 0) {
        printf("error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    nfnl_rcvbufsiz(nfnl_hl, NFQLENGTH * BUFLENGTH);

    int g_nfq_fd = nfq_fd(g_nfq_h);

    // start the nfq proxy thread
    nfq_stop = 0;
    pthread_t nfq_thread;
    struct nfq_loop_args* args = new struct nfq_loop_args();
    args->nfq_h = g_nfq_h;
    args->nfq_fd = g_nfq_fd;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, (void *)args) != 0){
        printf("Fail to create nfq thread.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

void *nfq_loop(void *arg)
{
    int rv;
    char buf[65536];

    struct nfq_loop_args* args = (struct nfq_loop_args*)arg;
    struct nfq_handle *g_nfq_h = args->nfq_h;
    int g_nfq_fd = args->nfq_fd;
    printf("nfq_loop for 0x%p, %d\n", g_nfq_h, g_nfq_fd);

    while (!nfq_stop) {
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            // printf("nfq_loop: count %d\n", count);
            // count++;
            //printf("%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //printfv("pkt received");
            nfq_handle_packet(g_nfq_h, buf, rv);
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("recv() ret %d errno: %d", rv, errno);
            }
            usleep(1); //10000
        }
    }
}

 static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data)
{

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        printf("nfq_get_msg_packet_hdr failed");
        return -1;
    }
    u_int32_t id = ntohl(ph->packet_id);
    //printf("packet id: %d", id);

    // get data (IP header + TCP header + payload)
    unsigned char *pkt_data;
    int plen = nfq_get_payload(nfa, &pkt_data);
    // fprintf(log, "id: %d, plen %d, count %d\n", id, plen, count);
    printf("id: %d, plen %d, count %d\n", id, plen, count);

    struct mypacket packet;
    packet.data = pkt_data;
    packet.len = plen;
    packet.iphdr = ip_hdr(pkt_data);

    int ret = -1;

    switch (packet.iphdr->protocol) {
        case 6: // TCP
        {
            packet.tcphdr = tcp_hdr(pkt_data);
            packet.payload = tcp_payload(pkt_data);
            packet.payload_len = packet.len - packet.iphdr->ihl*4 - packet.tcphdr->th_off*4;
            hex_dump(packet.payload, packet.payload_len);
            // printf("%s\n\n", hex_str);
            // free(hex_str);
            break;
        }
        default:
            printf("Invalid protocol: %d", packet.iphdr->protocol);
    }
    
    if (ret == 0){
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        // log_exp("verdict: accpet\n");
    }
    else{
        nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        // log_exp("verdict: drop\n");
    }
        
    // return <0 to stop processing
    count++;
    return 0;
}


int main(int argc, char *argv[]){
    log = fopen("test_multi_nfq.log","w");
    setup_nfq(5);
    setup_nfq(6);
    while (true) sleep(1000000);
}