#ifndef OPTIMACK_H
#define OPTIMACK_H

#include "thr_pool.h"
#include <set>
#include <map>
#include <vector>
#include <chrono>
#include <ctime>
#include <sys/time.h>
#include "interval.h"
// #include "comm/Connection.h"
// #include "../comm/forward.h"
// #include <bits/stdc++.h>
// using namespace std;


/** Our code **/
#define ACKPACING 2000
#define LOGSIZE 1024
#define IPTABLESLEN 128
// nfq
#define NF_QUEUE_NUM 6
#define NFQLENGTH 204800
#define BUFLENGTH 4096
// range
#define MAX_REQUEST_LEN 1024
#define MAX_RANGE_REQ_LEN 1536
#define MAX_RANGE_SIZE 102400
#define PACKET_SIZE 1448

class Optimack;

struct subconn_info
{
    int sockfd;
    unsigned short local_port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int next_seq_rem;  //rel
    unsigned int last_next_seq_rem;
    unsigned int next_seq_loc;  //TODO: rel
    short ack_sent;
    bool seq_init, fin_ack_recved;

    pthread_t thread;
    pthread_mutex_t mutex_opa;
    unsigned int optim_ack_stop;
    unsigned int opa_seq_start;  // local sequence number for optim ack to start
    unsigned int opa_ack_start;  // local ack number for optim ack to start
    unsigned int opa_seq_max_restart;
    unsigned int opa_retrx_counter;
    std::chrono::time_point<std::chrono::system_clock> last_restart_time, last_data_received, timer_print_log;
    int rwnd;
    int ack_pacing;
    unsigned int payload_len;
    float off_pkt_num;

    std::map<uint, uint> dup_seqs;
    IntervalList recved_seq;
    std::vector<Interval> seq_gaps;
    pthread_mutex_t mutex_seq_gaps;

    bool is_backup;
};

// Multithread
struct thread_data {
    unsigned int  pkt_id;
    unsigned int  len;
    unsigned char *buf;
    Optimack* obj;
};

struct int_thread {
    int thread_id;
    Optimack* obj;
};

// Thread wrapper
void* nfq_loop(void *arg);
void* pool_handler(void* arg);
void* optimistic_ack(void* arg);
void* overrun_detector(void* arg);
void* range_watch(void* arg);
void* send_all_requests(void* arg);

class Optimack
{
public:
    ~Optimack();
    void init();
    int setup_nfq(unsigned short id);
    int setup_nfqloop();
    void open_one_duplicate_conn(std::vector<struct subconn_info> *subconn_info_list, bool is_backup);
    void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, int fd);
    int teardown_nfq();
    int exec_iptables(char action, char* rule);
    void cleanup();
    void log_seq_gaps();

    struct nfq_handle *g_nfq_h;
    struct nfq_q_handle *g_nfq_qh;
    int g_nfq_fd;
    int nfq_stop, overrun_stop, cb_stop;
    pthread_t nfq_thread, overrun_thread;

    bool is_nfq_full(FILE* out_file);
    bool does_packet_lost_on_all_conns();
    // int find_seq_gaps(unsigned int seq);
    // void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step);
    // void delete_seq_gaps(unsigned int val);
    int start_optim_ack(int id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int start_optim_ack_backup(int id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int restart_optim_ack(int id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer);
    int process_tcp_packet(struct thread_data* thr_data);

    // variables
    int main_fd;
    char g_local_ip[16]; //TODO: different connection from client
    char g_remote_ip[16];
    unsigned int g_local_ip_int;
    unsigned int g_remote_ip_int;
    unsigned short g_remote_port;
    char request[1000];
    unsigned short request_len;
    struct sockaddr_in dstAddr;
    
    std::vector<struct subconn_info> subconn_infos, backup_subconn_infos;

    std::vector<char*> iptables_rules;
    
    // locals
    bool request_recved = false;
    const int MARK = 666;
    int nfq_queue_num;
    
    thr_pool_t* pool;
    pthread_mutex_t mutex_seq_next_global = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_subconn_infos = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_optim_ack_stop = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_cur_ack_rel = PTHREAD_MUTEX_INITIALIZER;
    
    // seq
    IntervalList recved_seq;
    pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
    // std::vector<Interval> seq_gaps, recved_seq;
    std::map<std::string, uint> bytes_per_second;

    // std::std::vector<unsigned int*> seq_gaps;
    unsigned int seq_next_global = 1,
                 cur_ack_rel = 1,
                 rwnd = 1,
                 win_scale = 1 << 7,
                 max_win_size = 0,
                 last_ack_rel = 0,
                 last_speedup_ack_rel = 1,
                 last_slowdown_ack_rel = 0,
                 same_ack_cnt = 0; 
    float last_off_packet = 0.0;
    std::chrono::time_point<std::chrono::system_clock> last_speedup_time, last_rwnd_write_time, last_same_ack_time, last_restart_time;
    FILE *log_file, *rwnd_file, *adjust_rwnd_file, *seq_file, *ack_file, *seq_gaps_file, *seq_gaps_count_file, *lost_per_second_file, *tcpdump_pipe;
    char output_dir[100];
    char *home_dir;
    char start_time[20], tcpdump_file_name[100], mtr_file_name[100], loss_file_name[100], seq_gaps_count_file_name[100], info_file_name[100];

    // range
    int init_range();
    int send_http_range_request(uint start, uint end);
    pthread_mutex_t mutex_range = PTHREAD_MUTEX_INITIALIZER;
    int range_sockfd;
};


#endif
