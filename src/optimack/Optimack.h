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
#include <netinet/in.h>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include "tls.h"
#endif
// #include "comm/Connection.h"
// #include "../comm/forward.h"
// #include <bits/stdc++.h>
// using namespace std;

#define USE_OPTIMACK 1


class Optimack;

struct subconn_info
{
    int id;
    int sockfd;
    unsigned short local_port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int next_seq_rem;  //rel
    unsigned int last_next_seq_rem;
    unsigned int next_seq_loc;  //TODO: rel
    short ack_sent;
    bool seq_init;

    pthread_t thread;
    pthread_mutex_t mutex_opa;
    unsigned int optim_ack_stop;
    unsigned int opa_seq_start;  // local sequence number for optim ack to start
    unsigned int opa_ack_start;  // local ack number for optim ack to start
    unsigned int opa_seq_max_restart;
    unsigned int opa_retrx_counter;
    std::chrono::time_point<std::chrono::system_clock> last_restart_time, last_data_received, timer_print_log, last_inorder_data_time;
    int rwnd;
    int win_scale;
    int ack_pacing;
    unsigned int payload_len;
    float off_pkt_num;
    unsigned int stall_seq;
    int restart_counter;

    std::map<uint, uint> dup_seqs;
    IntervalList recved_seq;
    // std::vector<Interval> seq_gaps;
    // pthread_mutex_t mutex_seq_gaps;

    bool is_backup;
    bool fin_or_rst_recved;
    bool handshake_finished;
#ifdef USE_OPENSSL
    SSL *ssl;
    TLS_Crypto_Coder crypto_coder;
    int record_size;
    unsigned int next_seq_rem_tls; //for tls's optimack overrun recover, otherwise recover won't work
    // uint ini_seq_tls_data;
    // unsigned char *iv_salt, *session_key;
#endif
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
void* send_all_requests(void* arg);

void* range_watch(void* arg);
// void* range_recv(void* arg);


class Optimack
{
public:
    Optimack();
    ~Optimack();
    void init();
    int setup_nfq(unsigned short id);
    int setup_nfqloop();
    struct subconn_info *create_subconn_info(int sockfd, bool is_backup); 
    int insert_subconn_info(std::map<uint, struct subconn_info*> &subconn_infos, uint& subconn_count, struct subconn_info* new_subconn);
    void open_one_duplicate_conn(std::map<uint, struct subconn_info*> &subconn_info_list, bool is_backup);
    void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, int fd);
    int teardown_nfq();
    int exec_iptables(char action, char* rule);
    void cleanup();
    void log_seq_gaps();
    void print_seq_table();

    struct nfq_handle *g_nfq_h;
    struct nfq_q_handle *g_nfq_qh;
    int g_nfq_fd;
    int nfq_stop, overrun_stop, cb_stop, optim_ack_stop;
    pthread_t nfq_thread, overrun_thread, optim_ack_thread;

    bool is_nfq_full(FILE* out_file);
    void print_ss(FILE* out_file);
    bool does_packet_lost_on_all_conns();
    int get_localport(int fd);
    // int find_seq_gaps(unsigned int seq);
    // void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step);
    // void delete_seq_gaps(unsigned int val);
    int start_optim_ack(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int start_optim_ack_backup(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int start_optim_ack_altogether(unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max);
    int restart_optim_ack(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer);
    int send_ACK_adjusted_rwnd(struct subconn_info* conn, int cur_ack);
    int send_optimistic_ack_with_timer(struct subconn_info* conn, int cur_ack, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window);
    int process_tcp_packet(struct thread_data* thr_data);
    int process_tcp_packet_with_payload(struct mytcphdr* tcphdr, unsigned int seq_rel, unsigned char* payload, int payload_len, struct subconn_info* subconn, char* log);
    int process_tcp_ciphertext_packet(int pkt_id, struct mytcphdr* tcphdr, unsigned int seq, unsigned int ack, unsigned char *tcp_opt, unsigned int tcp_opt_len, unsigned char* payload, int payload_len, bool incoming, subconn_info* subconn, char* log);
    int process_tcp_plaintext_packet(int pkt_id, unsigned char* packet, int packet_len, struct mytcphdr* tcphdr, unsigned int seq, unsigned int ack, unsigned char *tcp_opt, unsigned int tcp_opt_len, unsigned char* payload, int payload_len, bool incoming, subconn_info* subconn, char* log);
    void send_optimistic_ack_with_SACK(struct subconn_info* conn, int cur_ack, int adjusted_rwnd, IntervalList* recved_seq);
    int modify_to_main_conn_packet(struct subconn_info* subconn, struct mytcphdr* tcphdr, unsigned char* packet, unsigned int packet_len, unsigned int seq_rel);
    void send_optimistic_ack(struct subconn_info* conn, int cur_ack, int adjusted_rwnd);
    int get_ajusted_rwnd(int cur_ack);
    int get_ajusted_rwnd_backup(int cur_ack);
    void update_optimistic_ack_timer(bool is_zero_window, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window);
    int generate_sack_blocks(unsigned char * buf,int len, IntervalList* sack_list, uint ini_seq_rem);
    void extract_sack_blocks(unsigned char * const buf, const uint16_t len, IntervalList& sack_list,  unsigned int ini_seq);
    void send_data_to_backup(unsigned int seq, unsigned char* payload, int payload_len);
    void send_data_to_squid(unsigned int seq, unsigned char* payload, int payload_len);
    void send_data_to_subconn(struct subconn_info* conn, unsigned int seq, unsigned char* payload, int payload_len);
    // void update_subconn_next_seq_loc(struct subconn_info* subconn, uint num, bool is_fin);
    void backup_try_fill_gap();
    void send_request(char* request, int len);

    void update_subconn_next_seq_rem(struct subconn_info* subconn, uint num, bool is_fin);

    bool try_update_uint(uint &src, uint target);
    bool try_update_uint_with_lock(pthread_mutex_t* mutex, uint &src, uint target);

    struct subconn_info* get_slowest_subconn();



    // variables
    int main_fd;
    char g_local_ip[16]; //TODO: different connection from client
    char g_remote_ip[16];
    unsigned int g_local_ip_int;
    unsigned int g_remote_ip_int;
    unsigned short g_remote_port;
    unsigned short squid_port, backup_port;
    char *request, *response;
    unsigned short request_len, response_len;
    struct sockaddr_in dstAddr;
    uint squid_MSS;
    
    std::map<uint, struct subconn_info*> subconn_infos;
    uint subconn_count;
    // std::vector<struct subconn_info> subconn_infos, backup_subconn_infos;

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
    IntervalList recved_seq, all_lost_seq, we2squid_lost_seq, sack_list;
    pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
    // std::vector<Interval> seq_gaps, recved_seq;
    std::map<std::string, uint> bytes_per_second;

    // std::std::vector<unsigned int*> seq_gaps;
    unsigned int seq_next_global = 1,
                 cur_ack_rel = 1,
                 last_ack_rel = 0,
                 last_speedup_ack_rel = 1,
                 last_slowdown_ack_rel = 0,
                 max_opt_ack = 0; 
    unsigned int backup_dup_ack = 0, backup_max_opt_ack = 0;
    int win_scale = 1 << 7, 
        rwnd = 1, adjusted_rwnd = 0, win_end = 1, backup_dup_ack_rwnd = 1,
        max_win_size = 0,
        same_ack_cnt = 0,
        overrun_cnt = 0,
        we2squid_lost_cnt = 0,
        range_timeout_cnt = 0;
    float overrun_penalty = 0, we2squid_penalty = 0, range_timeout_penalty = 0;

    float last_off_packet = 0.0;
    std::chrono::time_point<std::chrono::system_clock> last_speedup_time, last_rwnd_write_time, last_ack_time, last_restart_time, start_timestamp;
    double last_ack_epochtime, last_inorder_data_epochtime;
    FILE *log_file, *rwnd_file, *adjust_rwnd_file, *forward_seq_file, *recv_seq_file, *processed_seq_file, *ack_file, *seq_gaps_file, *seq_gaps_count_file, *lost_per_second_file, *tcpdump_pipe;
    char output_dir[100];
    char home_dir[10];
    char hostname[20], start_time[20], tcpdump_file_name[100], mtr_file_name[100], loss_file_name[100], seq_gaps_count_file_name[100], info_file_name[100];

    // range
    int establish_tcp_connection(int old_sockfd);
    void try_for_gaps_and_request();
    bool check_packet_lost_on_all_conns(uint last_recv_inorder);
    uint get_byte_seq(uint tcp_seq);
    uint get_tcp_seq(uint byte_seq);
    int get_lost_range(Interval* intvl);
    int get_http_response_header_len(unsigned char* payload, int payload_len);
    //IntervalList* get_lost_range(uint start, uint end);
    int send_http_range_request(void* sockfd, Interval range);
    void start_range_recv(IntervalList* list);
    void we2squid_loss_and_start_range_recv(uint start, uint end, IntervalList* intvl_lis);
    void we2squid_loss_and_insert(uint start, uint end);
    uint get_min_next_seq_rem();
    pthread_t range_thread;
    pthread_mutex_t mutex_range = PTHREAD_MUTEX_INITIALIZER;
    int range_stop, range_sockfd, range_request_count = 0;
    IntervalList ranges_sent;
    uint response_header_len = 0, requested_bytes = 0, file_size = 0, ack_end = 1;

    //receive buffer
    struct data_segment{
        unsigned char* data;
        int len;
        data_segment() 
        { data = NULL; len = 0; }
        data_segment(unsigned char* data_, int len_)
        { data = data_; len = len_; }
    };
    std::map<uint, struct data_segment> recv_buffer;
    pthread_mutex_t mutex_recv_buffer = PTHREAD_MUTEX_INITIALIZER;
    int insert_to_recv_buffer(uint seq, unsigned char* data, int len);
    int insert_to_recv_buffer_withLock(uint seq, unsigned char* data, int len);
    int remove_recved_recv_buffer(uint seq);
    int remove_recved_recv_buffer_withLock(uint seq);
    int send_out_of_order_recv_buffer(uint seq);
    int send_out_of_order_recv_buffer(uint start, uint end);
    int send_out_of_order_recv_buffer(uint start, uint end, int max_count);
    int send_out_of_order_recv_buffer_withLock(uint seq);
    int send_out_of_order_recv_buffer_withLock(uint start, uint end, int max_count);
    int send_out_of_order_recv_buffer_withLock(uint start, uint end);
    int resend_cnt = 0;

    //TLS
    bool is_ssl = false;
#ifdef USE_OPENSSL
    TLS_Decrypted_Records_Map decrypted_records_map;
    int open_duplicate_ssl_conns(SSL *squid_ssl);
    int set_subconn_ssl_credentials(struct subconn_info *subconn, SSL *ssl);
    int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int partial_decrypt_tcp_payload(uint seq, unsigned char* payload, int payload_len);
    int partial_decrypt_tcp_payload(struct subconn_info* subconn, uint seq, unsigned char* payload, int payload_len);
#endif
};

double get_current_epoch_time_second();
double get_current_epoch_time_nanosecond();
double elapsed(std::chrono::time_point<std::chrono::system_clock> start);

#endif
