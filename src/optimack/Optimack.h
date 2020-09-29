#ifndef NETFILTER_QUEUE_H
#define NETFILTER_QUEUE_H

#include "thr_pool.h"
#include <set>
#include <vector>

/** Our code **/
#define ACKPACING 1000
// TODO: cleanup()
#define LOGSIZE 1024
// nfq
#define NF_QUEUE_NUM 6

class Optimack;

struct subconn_info
{
    unsigned short local_port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int cur_seq_rem;
    unsigned int cur_seq_loc;
    short ack_sent;

    pthread_t thread;
    pthread_mutex_t mutex_opa;
    unsigned int optim_ack_stop;
    unsigned int opa_seq_start;  // local sequence number for optim ack to start
    unsigned int opa_ack_start;  // local ack number for optim ack to start
    unsigned int opa_seq_max_restart;
    unsigned int opa_retrx_counter;
    unsigned int win_size;
    int ack_pacing;
    unsigned int payload_len;
};

// Multithread
struct thread_data {
    unsigned int  pkt_id;
    unsigned int  len;
    unsigned char *buf;
    Optimack* obj;
};

struct ack_thread {
    int thread_id;
    Optimack* obj;
};

// Thread wrapper
void* nfq_loop(void *arg);
void* pool_handler(void* arg);
void* optimistic_ack(void* arg);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

class Optimack
{
public:
    void init();
    int setup_nfq(void* data);
    int setup_nfqloop();
    void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, 
            unsigned short local_port);
    int teardown_nfq();

    struct nfq_handle *g_nfq_h;
    struct nfq_q_handle *g_nfq_qh;
    int g_nfq_fd;
    int nfq_stop;
    pthread_t nfq_thread;

    int find_seq_gaps(unsigned int seq);
    void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step);
    void delete_seq_gaps(unsigned int val);
    int start_optim_ack(int id, unsigned int seq, unsigned int ack, unsigned int payload_len, 
            unsigned int seq_max);
    int process_tcp_packet(struct thread_data* thr_data);

    // variables
    char g_local_ip[16]; //TODO: different connection from client
    char g_remote_ip[16];
    unsigned int g_local_ip_int;
    unsigned int g_remote_ip_int;
    unsigned short g_remote_port;
    char request[1000];
    unsigned short request_len;
    
    std::vector<struct subconn_info> subconn_infos;
    
    // locals
    bool request_recved = false;
    const int MARK = 666;
    
    thr_pool_t* pool;
    pthread_mutex_t mutex_seq_next_global = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_subconn_infos = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_optim_ack_stop = PTHREAD_MUTEX_INITIALIZER;
    
    // seq
    unsigned int seq_next_global = 1;
    std::set<unsigned int> seq_gaps;
    unsigned int max_win_size = 0;
    unsigned int last_speedup_ack_rel = 1;
};

#endif