#ifndef NETFILTER_QUEUE_H
#define NETFILTER_QUEUE_H

/** Our code **/
// TODO: cleanup()
#define LOGSIZE 1024
// nfq
#define NF_QUEUE_NUM 6

struct nfq_handle *g_nfq_h;
struct nfq_q_handle *g_nfq_qh;
int g_nfq_fd;
int nfq_stop;

char g_local_ip[16]; //TODO: different connection from client
char g_remote_ip[16];
unsigned short g_remote_port;
char request[1000];

// Optim ack
std::vector<struct subconn_info> subconn_infos;
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
char* empty_payload;

// Multithread
struct thread_data {
    unsigned int  pkt_id;
    unsigned int  len;
    unsigned char *buf;
};


// protos
void init();
int setup_nfq(void* data);
void *nfq_loop(void *arg);
int find_seq_gaps(unsigned int seq);
void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step);
void delete_seq_gaps(unsigned int val);
void* optimistic_ack(void* threadid);
int start_optim_ack(int id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
int process_tcp_packet(struct thread_data* thr_data);
void* pool_handler(void* arg);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data);

void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port);


#endif