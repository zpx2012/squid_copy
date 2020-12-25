#ifndef NETFILTER_QUEUE_H
#define NETFILTER_QUEUE_H

#include "thr_pool.h"
#include <set>
#include <vector>
#include <chrono>
#include <ctime>
#include <sys/time.h>

class CurrentTime{
public:
    CurrentTime() {}
    char* time_in_HH_MM_SS(){
        // time(&rawtime);
        gettimeofday (&cur_timeval, NULL);
        timeinfo = localtime(&cur_timeval.tv_sec);
        strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
        return time_str;
    }
    char* time_in_HH_MM_SS_US(){
        gettimeofday(&cur_timeval, NULL);
        timeinfo = localtime(&cur_timeval.tv_sec);
        strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
        sprintf(time_str, "%s.%06ld", time_str, cur_timeval.tv_usec);
        return time_str;
    }

private:
    char time_str[64];
    time_t rawtime;
    struct tm * timeinfo;
    timeval cur_timeval;
};


/** Our code **/
#define ACKPACING 1000
#define LOGSIZE 1024
#define IPTABLESLEN 128
// nfq
#define NF_QUEUE_NUM 6
#define NFQLENGTH 1024*200
#define BUFLENGTH 4096

class Optimack;

struct subconn_info
{
    int sockfd;
    unsigned short local_port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int cur_seq_rem;
    unsigned int cur_seq_loc;
    short ack_sent;
    bool seq_init;

    pthread_t thread;
    pthread_mutex_t mutex_opa;
    unsigned int optim_ack_stop;
    unsigned int opa_seq_start;  // local sequence number for optim ack to start
    unsigned int opa_ack_start;  // local ack number for optim ack to start
    unsigned int opa_seq_max_restart;
    unsigned int opa_retrx_counter;
    // unsigned int rwnd;
    int ack_pacing;
    unsigned int payload_len;
    float off_pkt_num;
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

class Optimack
{
public:
    ~Optimack();
    void init();
    int setup_nfq(unsigned short id);
    int setup_nfqloop();
    void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, 
            unsigned short local_port);
    int teardown_nfq();
    int exec_iptables(char action, char* rule);
    void cleanup();

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
    struct sockaddr_in dstAddr;
    
    std::vector<struct subconn_info> subconn_infos;

    std::vector<char*> iptables_rules;
    
    // locals
    bool request_recved = false;
    const int MARK = 666;
    int nfq_queue_num;
    
    thr_pool_t* pool;
    pthread_mutex_t mutex_seq_next_global = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_subconn_infos = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_optim_ack_stop = PTHREAD_MUTEX_INITIALIZER;
    
    // seq
    std::set<unsigned int> seq_gaps;
    unsigned int seq_next_global = 1,
                 cur_ack_rel = 1,
                 rwnd = 1,
                 win_scale = 1 << 8,
                 max_win_size = 0,
                 last_ack_rel = 0,
                 last_speedup_ack_rel = 1,
                 last_slowdown_ack_rel = 0,
                 same_ack_cnt = 0; 
    float last_off_packet = 0.0;
    std::chrono::time_point<std::chrono::system_clock> last_speedup_time, last_rwnd_write_time;
    FILE *log_file, *rwnd_file, *adjust_rwnd_file;

    CurrentTime cur_time;
};


#endif
