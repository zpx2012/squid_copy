#include <string.h>
#include <algorithm>
#include <arpa/inet.h> //ntohl
#include <unistd.h> //close
#include <netinet/in.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include "logging.h"
#include "Optimack.h"
#include "socket.h"
#include <condition_variable>
#include <mutex>
#include "checksum.h"
// #include "thr_pool_range.h"

#ifndef GPROF_CHECK
#include "squid.h"
#include "sbuf/SBuf.h"
#include "http/one/RequestParser.h"
#include "http/one/ResponseParser.h"
#endif


// range
#define MAX_REQUEST_LEN 1024
#define MAX_RANGE_REQ_LEN 1536
#define PACKET_SIZE 1460

// #define GROUP_NUM 6
// #define RANGE_NUM 6
const int GROUP_NUM = 10;
const int RANGE_NUM = 3;

#define MAX_RANGE_REQ_CNT 98
#define REQ_STEP 5
#define BASE_RANGE_REQ_CNT MAX_RANGE_REQ_CNT - GROUP_NUM * REQ_STEP

const bool debug_range = false;
const bool split_range = false;
const bool single_sender = false;
// const bool use_nfq = true;
#define USE_NFQ 1
const int MAX_REQUEST_CNT = 1;
std::condition_variable range_send_cv;
std::mutex range_send_cv_m;


// int process_range_rv(char* response, int rv, std::shared_ptr<Optimack> obj, subconn_info* subconn, std::vector<Interval> range_job_vector, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);
int process_range_rv_old(char* response, int rv, Optimack* obj, subconn_info* subconn, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);
void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);


int establish_tcp_connection(int old_sockfd, char* remote_ip, unsigned short remote_port, int& port, int mark)
{
    int sockfd = 0;
    struct sockaddr_in server_addr;

    // Open socket
opensocket:
    while(sockfd == 0 || sockfd == old_sockfd){ //|| 
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Can't open stream socket.");
            return -1;
        }
        if(debug_range) print_func("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_ip);
    server_addr.sin_port = htons(remote_port);

    // struct timeval tv;
    // tv.tv_sec = 10;
    // tv.tv_usec = 0;
    // setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    // if(mark)
    //     setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

    // Connect to server
    int count = 0;
    while (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 && count++ < 5) {
        print_func("establish_tcp_connection: sockfd %d connect error\n", sockfd);
        perror("Connect server error");
    }

    if(count >= 5){
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }

    port = get_localport(sockfd);
    if(port < 0){
        print_func("establish_tcp_connection: sockfd %d get_localport error\n", sockfd);
        sockfd = 0;
        close(sockfd);
        goto opensocket;
    }

    // print_func("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);

    return sockfd;
}


int establish_tcp_connection(int old_sockfd, char* remote_ip, unsigned short remote_port)
{
    int sockfd = 0;
    struct sockaddr_in server_addr;

    // Open socket
opensocket:
    while(sockfd == 0 || sockfd == old_sockfd){ //|| 
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Can't open stream socket.");
            return -1;
        }
        if(debug_range) print_func("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_ip);
    server_addr.sin_port = htons(remote_port);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        /* Set the option active */
    int optval = 1;
    socklen_t optlen = sizeof(optval);
    if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        perror("setsockopt()");
    }
    else
        print_func("establish_tcp_connection: sockfd %d SO_KEEPALIVE set on socket", sockfd);

        
    // Connect to server
    int count = 0;
    while (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 && count++ < 5) {
        print_func("establish_tcp_connection: sockfd %d connect error\n", sockfd);
        perror("Connect server error");
    }

    if(count >= 5){
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }

    // print_func("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);

    return sockfd;
}


int open_range_conn(struct range_conn* cur_range_conn, char* remote_ip, unsigned short remote_port){
// #ifdef USE_OPENSSL
//         if(obj->is_ssl)
//             cur_range_conn->ssl_old = cur_range_conn->ssl;
// #endif
    cur_range_conn->sockfd_old = cur_range_conn->sockfd;
    int rv = 0;
    int mark_range = MARK_RANGE;
    while( (rv = establish_tcp_connection(cur_range_conn->sockfd_old, remote_ip, remote_port, cur_range_conn->port, mark_range)) <= 0 ) sleep(1);
    // setsockopt(rv, SOL_SOCKET, SO_MARK, &MARK_RANGE, sizeof(MARK_RANGE));
    // setsockopt(rv, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK));
    cur_range_conn->in_use = 0;
    cur_range_conn->sockfd = rv;
    cur_range_conn->range_request_count = 0;
    // cur_range_conn->in_use++;
    print_func("[Range]R%d-%d: sockfd %d, conn created, erase count %d", cur_range_conn->id, cur_range_conn->port, rv, cur_range_conn->erase_count);

    char cmd[100] = {0};
    snprintf(cmd, 100, "sudo iptables -A PREROUTING -t mangle -p tcp --dport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
    system(cmd);

    memset(cmd, 0, 100);
    snprintf(cmd, 100, "sudo iptables -A OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
    system(cmd);

    return 0;
}

// int init_range_conn(struct range_conn* cur_range_conn, char* remote_ip, unsigned short remote_port, int id, std::shared_ptr<Optimack> obj){
//     // memset(cur_range_conn, 0 , sizeof(struct range_conn));

//     // pthread_mutex_init(&cur_range_conn->mutex_opa, NULL);
//     // pthread_mutex_lock(&cur_range_conn->mutex_opa);
//     // std::lock_guard<std::mutex> lock(cur_range_conn->std_mutex);
//     cur_range_conn->std_mutex.lock();
//     cur_range_conn->id = id;
//     open_range_conn(cur_range_conn, remote_ip, remote_port, obj);
//     cur_range_conn->last_send = std::chrono::system_clock::now();
//     cur_range_conn->std_mutex.unlock();
    
//     // if(use_nfq){
// // #ifdef USE_NFQ
//     // }
// // #endif
//     return 0;
// }

int close_range_conn(struct range_conn* cur_range_conn){
    char cmd[100] = {0};
    snprintf(cmd, 100, "sudo iptables -D PREROUTING -t mangle -p tcp --dport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
    system(cmd);

    memset(cmd, 0, 100);
    snprintf(cmd, 100, "sudo iptables -D OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
    system(cmd);

    // close(cur_range_conn->sockfd);
    // delete (cur_range_conn->header);
    return 0;
}

// int reopen_range_conn(struct range_conn* cur_range_conn, char* remote_ip, unsigned short remote_port, std::shared_ptr<Optimack> obj){
//     // print_func("[Range]R%d-%d: start reopen conn, count %d, erase count %d", cur_range_conn->id, cur_range_conn->port, cur_range_conn->range_request_count, cur_range_conn->erase_count);
//     // pthread_mutex_lock(&cur_range_conn->mutex_opa);
//     // std::lock_guard<std::mutex> lock(cur_range_conn->std_mutex);

//     char cmd[100] = {0};
//     snprintf(cmd, 100, "sudo iptables -D PREROUTING -t mangle -p tcp --dport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
//     system(cmd);

//     memset(cmd, 0, 100);
//     snprintf(cmd, 100, "sudo iptables -D OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
//     system(cmd);

//     int old_sockfd = cur_range_conn->sockfd;
//     cur_range_conn->std_mutex.lock();
//     if(cur_range_conn->sockfd == old_sockfd){
//         close(cur_range_conn->sockfd);
//         cur_range_conn->erase_count += REQ_STEP;
//         if(cur_range_conn->erase_count > MAX_RANGE_REQ_CNT)
//             cur_range_conn->erase_count = (cur_range_conn->erase_count % MAX_RANGE_REQ_CNT) + BASE_RANGE_REQ_CNT ;
//         open_range_conn(cur_range_conn, remote_ip, remote_port, obj);
//     }
//     cur_range_conn->std_mutex.unlock();
//     // pthread_mutex_unlock(&cur_range_conn->mutex_opa);
//     return 0;
// }


int open_group_range_conn(struct range_conn** range_conns, int i, char* remote_ip, unsigned short remote_port, std::shared_ptr<Optimack> obj){

    struct range_conn* group_conns = range_conns[i];
    std::counting_semaphore<10> *smph = new std::counting_semaphore<10>(MAX_REQUEST_CNT);
    IntervalList* group_seq = new IntervalList();
    group_seq->insertNewInterval(1, UINT_MAX);

    // print_func("open_group_range_conn: opening group %d, %p, %p", (i+1), range_conns, group_conns);
    // for(int m = 0; m < GROUP_NUM*2; m++)
    //     print_func("open_group_range_conn: line267 group %d, %p", (m+1), range_conns[m]);


    for(int j = 0; j < RANGE_NUM; j++){
        struct range_conn* cur_range_conn = &(group_conns[j]);
        // print_func("open_group_range_conn: line 272 opening %d", (i+1)*100+j);
        memset(cur_range_conn, 0, sizeof(struct range_conn));
        // print_func("open_group_range_conn: done memset");
        cur_range_conn->id = (i+1)*100+j;
        cur_range_conn->smph = smph;
        cur_range_conn->group_recved_seq = group_seq;
        cur_range_conn->last_send = std::chrono::system_clock::now();
        cur_range_conn->erase_count = MAX_RANGE_REQ_CNT;
        open_range_conn(cur_range_conn, remote_ip, remote_port);
        // for(int m = 0; m < GROUP_NUM*2; m++)
            // print_func("open_group_range_conn: after open group %d, %p", (m+1), range_conns[m]);
        if(obj->info_file){
            if(obj->processed_seq_file) {
                fprintf(obj->processed_seq_file, "%f,creation,%d,%u,-1,-1\n", get_current_epoch_time_nanosecond(), cur_range_conn->id, cur_range_conn->port);
                // fflush(obj->processed_seq_file);
            }
            if(obj->info_file) {
                fprintf(obj->info_file, "Range_conn,%d,%d\n", cur_range_conn->port, cur_range_conn->id);
                fflush(obj->info_file);
            }
        }

    }

    print_func("open_group_range_conn: Group %d, for loop done", i+1);
    
    if(!single_sender){
        std::thread send_worker(&Optimack::send_group_range_request_worker, obj, range_conns, i);
        send_worker.detach();
    }

    return 0;
}




int Optimack::range_recv(struct range_conn* cur_range_conn){
    // Receiving packet
    int id = cur_range_conn->id, sockfd = cur_range_conn->sockfd, port = cur_range_conn->port;
    http_header* header = new struct http_header();
    memset(header, 0, sizeof(http_header));
#ifdef USE_OPENSSL
    SSL* ssl = cur_range_conn->ssl;
#endif
    print_func("[Range]R%d-%d: range_recv thread created", id, port);
    int rv = 0;
    char response[MAX_RANGE_SIZE+1] = {0};

    int recv_offset = 0;
    while(!range_stop){
        if(recv_offset == 0)
            memset(response, 0, MAX_RANGE_SIZE+1);
        if(is_ssl){
    #ifdef USE_OPENSSL
            rv = SSL_read(ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
    #endif
        }
        else{
            rv = recv(sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, 0);
        }
        if (rv > 0) {//&& rv < MAX_RANGE_SIZE
            // log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
            // print_func("[Range]R%d-%d: recved %d bytes", cur_range_conn->id, cur_range_conn->port, rv);
            if(cur_range_conn->id % 100 == 0){
                response[recv_offset+rv] = 0;
                // if(processed_seq_file)  fprintf(processed_seq_file, "%f,start recv,%d,-1,-1\n", get_current_epoch_time_nanosecond(), id);
                bool is_new = process_range_rv(id, port, header, response, rv + recv_offset, recv_offset);
                // if(processed_seq_file)  fprintf(processed_seq_file, "%f,after recv,%d,-1,-1\n", get_current_epoch_time_nanosecond(), id);
                if(header->remain == 0 && (is_new || header->start != 1400)){
                    if(!single_sender){
                        if(debug_range) print_func("[Range]R%d-%d: range received, release one", id, port);
                        cur_range_conn->smph->release();
                    }
                    else{
                        cur_range_conn->range_request_count--;
                        range_send_cv.notify_one();
                    }
                }
            }
            else{
                recv_offset = 0;
            }
        }
        else{
            if(rv == 0){
                // log_debug("[Range] recv ret %d, sockfd %d closed ", rv, sockfd);
                print_func("[Range]R%d-%d: recv ret %d, sockfd %d closed", id, port, rv, sockfd); // errno %d, errno,
            }
            else{
                // log_debug("[Range] error: ret %d errno %d", rv, errno);
                print_func("[Range]R%d-%d: error: ret %d, sockfd %d closed", id, port, rv, sockfd); // errno %d, errno
            }
            recv_offset = 0;
            // close(sockfd);
            // if(!single_sender){
            //     print_func("[Range]R%d-%d: range received, release one", id, port);
            //     cur_range_conn->smph->release();
            // }
            // else{
            //     cur_range_conn->range_request_count--;
            //     range_send_cv.notify_one();
            // }
            delete header;
            return -1;
        }
        usleep(10);
    }
    delete header;
    return 0;
}

int parse_response(http_header *head, char *response, int unread);

int Optimack::process_range_rv(int id, int port, http_header* header, char* response, int unread, int& recv_offset){

    bool is_new_segment = false;
    int consumed = 0;
    while (unread > 0) {
        if (!header->parsed) {
            // parse header
            int parsed = parse_response(header, response+consumed, unread);
            if (parsed <= 0) {
                // incomplete http header
                // keep receiving and parse in next response
                memmove(response, response+consumed, unread);
                recv_offset += unread - recv_offset;
                // log_error("[Range] incomplete http header, len %d\n", unread);
                // if(debug_range)    print_func("[Range]R%d-%d: incomplete http header, len %d, offset %d", id, port, unread, recv_offset);
                unread = 0;
            }
            else {
                // if(debug_range) print_func("[Range]R%d-%d: Header received %d - %d", id, port, header->start, header->end);
                header->start = get_tcp_seq(header->start);
                header->end = get_tcp_seq(header->end);
                recv_offset = 0;
                unread -= parsed;
                consumed += parsed;
            }
        }
        else {
            int consuming = header->remain >= unread? unread : header->remain;
            int seq_rel = (header->start + header->recved);
            int seq_rel_end = seq_rel + consuming -1;
            if(debug_range){
                print_func("[Range]R%d-%d: [%d, %d] data retrieved, remain %d, unread %d", id, port, seq_rel, seq_rel_end, header->remain, unread);
                    // log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
            }
            if (seq_rel + consuming > cur_ack_rel){
                // if(debug_range) print_func("[Range]R%d-%d: [%d, %d] data to send to squid", id, port, seq_rel, seq_rel_end);
                is_new_segment |= store_and_send_data(seq_rel, (u_char*)(response), consuming, (subconn_info*)port, true, id);
                if(debug_range) print_func("[Range]R%d-%d: [%d, %d] data sent to squid", id, port, seq_rel, seq_rel_end);
            }
            header->recved += consuming;
            header->remain -= consuming;
            unread -= consuming;
            consumed += consuming;
            // if(header->start != 1001 || header->start != 10001){
            //     if(debug_range) print_func("[Range]R%d-%d: acquring lock", id, port);
            //     pthread_mutex_lock(&mutex_range);
            //     ranges_sent.removeInterval_updateTimer(seq_rel, seq_rel_end);
            //     if(debug_range) print_func("[Range]R%d-%d: [%d, %d] request removed", id, port, seq_rel, seq_rel_end);
            //     pthread_mutex_unlock(&mutex_range);
            //     if(debug_range) print_func("[Range]R%d-%d: releasing lock", id, port);
            // }

            if(header->remain == 0){
                memset(header, 0, sizeof(struct http_header));
            }
        }
    }

    return is_new_segment;
}



int parse_response(http_header *head, char *response, int unread)
{
    // const char header_field[] = "HTTP/1.1 206";
    const char range_field[] = "Content-Range: bytes ";
    const char multirange_field[] = "Content-range: bytes ";
    const char tail_field[] = "\r\n\r\n";
    // const char keep_alive_field[] = "Keep-Alive: ";
    // const char max_field[] = "max=";

    char *recv_end = response + unread;
    char *parse_head = response;
    if (head->parsed) {
        log_debug("[Range] error: header should have been parsed");
        return -1;
    }
    // check header
    // parse_head = std::search(response, recv_end, header_field, header_field+12);
    // if (parse_head < recv_end) {
        // check range
        parse_head = std::search(response, recv_end, range_field, range_field+21);
        if(parse_head == recv_end)
            parse_head = std::search(response, recv_end, multirange_field, multirange_field+21);

        if (parse_head < recv_end) {
            parse_head += 21;
            if(parse_head < recv_end){
                head->start = (int)strtol(parse_head, &parse_head, 10);
                parse_head++;
                if(parse_head < recv_end){
                    head->end = (int)strtol(parse_head, &parse_head, 10);
                    if(head->end < head->start){
                        head->start = 0;
                        head->end = 0;
                        return 0;
                    }
                    head->remain = head->end - head->start + 1;
                    head->recved = 0;
                    parse_head = std::search(parse_head, recv_end, tail_field, tail_field+4);
                    if (parse_head < recv_end) {
                        parse_head += 4;
                        head->parsed = 1;
                        return parse_head-response;
                    }
                }
            }
        }
    // }
    return 0;
}

int Optimack::send_group_range_request_worker(struct range_conn** range_conns, int group_i){
    struct range_conn* group_conns = range_conns[group_i];
    uint group_conns_size = sizeof(struct range_conn)*RANGE_NUM;
    std::counting_semaphore<10> *smph = group_conns[0].smph;
    IntervalList* group_recved_seq = group_conns[0].group_recved_seq;
    int backup_i = (group_i + GROUP_NUM) % (GROUP_NUM * 2);
    // struct range_conn* backup_conns;
    // struct range_conn backup_conns[RANGE_NUM];
    // memset(backup_conns, 0, group_conns_size);
    // std::chrono::time_point<std::chrono::system_clock> backup_create_time = std::chrono::system_clock::now();
    
    std::thread recv_threads[RANGE_NUM];
    for(int j=0; j < RANGE_NUM; j++){
        recv_threads[j] = std::thread(&Optimack::range_recv, getptr(), &group_conns[j]);
        // recv_threads[j].detach();
    }


    while(!range_stop){

        if (recved_seq.size() < 2 || recved_seq.getFirstStart() == 1 || !range_request_template_len){
            usleep(100);
            continue;
        }

        // if(processed_seq_file)  fprintf(processed_seq_file, "%f,before acquire,%d,-1,-1\n", get_current_epoch_time_nanosecond(), (group_i+1)*100);
        group_conns[0].smph->acquire();
        // if(processed_seq_file)  fprintf(processed_seq_file, "%f,after acquire,%d,-1,-1\n", get_current_epoch_time_nanosecond(), (group_i+1)*100);
        interval_map gaps = recved_seq.getGapsAndUpdateTimer(get_min_next_seq_rem(), 1, 4);
        // auto it = range_job_vector.begin(); 
        // while(range_job_vector.size() != 0 && it != range_job_vector.end()){
        //     if (cur_ack_rel >= it->end){
        //         it = range_job_vector.erase(it);
        //         continue;
        //     }

        //     double current_time = get_current_epoch_time_nanosecond();
        //     if(!it->sent_epoch_time || (current_time - it->sent_epoch_time >= 4)){
        //         if(it->sent_epoch_time){
        //             print_func("[Range]: [%u, %u] timeout", it->start, it->end);
        //             smph->release();
        //         }
        //         it->sent_epoch_time = current_time;
        //         gap_start = it->start;
        //         gap_end = it->end;
        //         found = true;
        //         break;
        //     }
        // }
        // ranges_sent.unlock();
        // if(processed_seq_file)  fprintf(processed_seq_file, "%f,unlock,%d,-1,-1\n", get_current_epoch_time_nanosecond(), (group_i+1)*100);


        if(gaps.size()){
            uint start = gaps.begin()->first.lower(), end = gaps.begin()->first.upper()-1;
            if(gaps.begin()->second == REQUEST_TIMEOUT)
                if(processed_seq_file)  fprintf(processed_seq_file, "%f,request timeout,%d,%u, %u,%u\n", get_current_epoch_time_nanosecond(), group_conns[0].id, group_conns[0].port, start, end+1);
            group_conns[0].last_send = std::chrono::system_clock::now();
            // if(group_conns[0].range_request_count < 95){
                std::thread send_group_range_request_thread(&Optimack::send_group_one_range_request, getptr(), group_conns, start, end);
                send_group_range_request_thread.detach();
            // }
            // else{
            //     send_group_one_range_request(group_conns, start, end);
            // }

            // int ret = send_group_one_range_request(group_conns, start, end);
            // if(ret < 0){
            //     print_func("send_group_range_request_worker: restart group_conns");
            //     if(!backup_conns){
            //         backup_conns = new struct range_conn[RANGE_NUM];
            //         open_group_range_conn(backup_conns, group_i, g_remote_ip, g_remote_port, getptr());
            //     }

            //     for(int j=0; j < RANGE_NUM; j++)
            //         close_range_conn(&group_conns[j]);
            //     //free(range_conns[i]);
            //     range_conns[group_i] = backup_conns;
            //     group_conns = backup_conns;
            //     backup_conns = NULL;
            // }
            if(++group_conns[0].range_request_count == 80){
                // backup_conns = new struct range_conn[RANGE_NUM];
                std::thread open_worker(open_group_range_conn, range_conns, backup_i, g_remote_ip, g_remote_port, getptr());
                open_worker.detach();
                print_func("[Group]G%d: start switching to %d", group_i+1, backup_i+1);
                // backup_create_time = std::chrono::system_clock::now();

            }
            else if(group_conns[0].range_request_count == group_conns[0].erase_count){ // || (backup_conns && elapsed(backup_create_time) > 3.8) || (range_conns[backup_i][RANGE_NUM-1].sockfd)
                break;
                // for(int j=0; j < RANGE_NUM; j++)
                //     close_range_conn(&group_conns[j]);
                //free(range_conns[i]);
                // range_conns[group_i] = backup_conns;
                // group_conns = backup_conns;
                // backup_conns = NULL;
                // memcpy(group_conns, backup_conns, group_conns_size);
                // memset(backup_conns, 0, group_conns_size);
            }
        }
        else{
            group_conns[0].smph->release();
            usleep(10);
        }

    }
    sleep(4);
    print_func("[Group]G%d: close conns", group_i+1);
    for(int j=0; j < RANGE_NUM; j++){
        print_func("[Group]R%d: close sockfd %d", group_conns[j].id, group_conns[j].sockfd);
        close(group_conns[j].sockfd);
    }

    for(int j=0; j < RANGE_NUM; j++){
        recv_threads[j].join();
        close_range_conn(&group_conns[j]);
        memset(&group_conns[j], 0, sizeof(struct range_conn));
    }
    delete smph;
    delete group_recved_seq;

    print_func("[Group]G%d: send_group_one_range_request, existting...\n", group_i+1);
    return 0;
}


int Optimack::send_group_one_range_request(struct range_conn* group_conns, uint start_seq, uint end_seq){
    if(debug_range) print_func("[Range]: group %d, [%u, %u] request to send, No.%d", group_conns[0].id/100, start_seq, end_seq, group_conns[0].range_request_count);
    

    int rv = 1;
    char request_str[1000];
    snprintf(request_str, 1000, "%s%u-%u\r\n\r\n", range_request_template, get_byte_seq(start_seq), get_byte_seq(end_seq));
    for(int j = 0; j < RANGE_NUM; j++){
        struct range_conn* cur_range_conn = &group_conns[j];
        // cur_range_conn->std_mutex.lock();
        // if(cur_range_conn->range_request_count == cur_range_conn->erase_count)
        //     reopen_range_conn(cur_range_conn, g_remote_ip, g_remote_port, getptr());

        rv *= send_http_range_request(cur_range_conn, request_str);
        // print_func("send_group_one_range_request: R%d, rv %d", j, rv);
        if(start_seq != 1001 && rv > 0)
            if(processed_seq_file)   fprintf(processed_seq_file, "%f,request,%d,%u,%u,%u\n", get_current_epoch_time_nanosecond(), cur_range_conn->id, cur_range_conn->port, start_seq, end_seq);

        // cur_range_conn->std_mutex.unlock();
    }
    return rv;
}




// int send_group_range_request_handler(std::shared_ptr<Optimack> obj, struct range_conn* range_conns, int group_i, std::ostringstream & ostr_i, std::ostringstream& pstr_i, int & quotas_i){
//     // print_func("[Range]: group %d, range_str pstr %s, ostr %s", group_i+1, pstr_i.str().c_str(), ostr_i.str().c_str());
//     // sprintf(range_str_start, "%s\r\n\r\n", ostr.str().c_str());
//     int ostr_cstr_len = ostr_i.str().size();
//     char* ostr_cstr = new char[ostr_cstr_len+1];
//     strncpy(ostr_cstr, ostr_i.str().c_str(), ostr_cstr_len);
//     ostr_cstr[ostr_cstr_len] = 0;
//     range_conns[group_i * RANGE_NUM].last_send = std::chrono::system_clock::now();
//     std::thread send_group_range_request_thread(&Optimack::send_group_range_request, obj, range_conns, group_i * RANGE_NUM, ostr_cstr);
//     send_group_range_request_thread.detach();

//     ostr_i.str(std::string());
//     pstr_i.str(std::string());
//     // quotas_i = 0;
//     return 0;
// }



// int Optimack::send_group_range_request(struct range_conn* range_conns, const int group_start_i, char* ranges_str){
//     if(debug_range) print_func("[Range]: group %d, range_str %s", group_start_i/RANGE_NUM+1, ranges_str);
//     // if(strcmp(ranges_str, "1001-1001") != 0)
//     //     if(processed_seq_file)   fprintf(processed_seq_file, "%f,request,%d,%s\n", get_current_epoch_time_nanosecond(), (group_start_i/RANGE_NUM+1)*100, ranges_str);
//     // signal(SIGPIPE, signal_callback_handler);

//     int rv = 0;
//     char request_str[1000];
//     snprintf(request_str, 1000, "%s%s\r\n\r\n", range_request_template, ranges_str);
//     for(int j = 0; j < RANGE_NUM; j++){
//         struct range_conn* cur_range_conn = &range_conns[group_start_i+j];
//         // cur_range_conn->std_mutex.lock();
//         rv = send_http_range_request(cur_range_conn, request_str);
//         // cur_range_conn->std_mutex.unlock();
//     }
//     delete[] ranges_str;
//     return rv;
// }


int Optimack::send_http_range_request(struct range_conn* cur_range_conn, const char* range_request_str){
    if(!range_request_str){
        print_func("send_http_range_request: range_request str is null");
        return 0;
    }

    cur_range_conn->std_mutex.lock();

    if(!cur_range_conn->sockfd) {
        print_func("R%d-%d: send_http_range_request: sockfd is 0", cur_range_conn->id, cur_range_conn->port);
        cur_range_conn->std_mutex.unlock();
        return 0;
    }

resend:
    int rv = -1;
    // for(int i = 0; (i < 1); i++){
        if(is_ssl){
    #ifdef USE_OPENSSL
            rv = SSL_write(cur_range_conn->ssl, range_request_str, strlen(range_request_str));
    #endif
        }
        else{
            rv = send(cur_range_conn->sockfd, range_request_str, strlen(range_request_str), MSG_NOSIGNAL);
            // for(int i = range->start; i+squid_MSS < range->end; i += squid_MSS){
            //     double ct = get_current_epoch_time_nanosecond();
            //     fprintf(forward_seq_file, "%f, %u\n", ct, i);
            // }
        }
        // if(rv > 0)
        //     break;
        // usleep(10);
    // }

    if(rv > 0){
        // if(debug_range) print_func("[Range]R%d-%d: request sent", cur_range_conn->id, cur_range_conn->port);
        cur_range_conn->last_send = std::chrono::system_clock::now();
        cur_range_conn->requested_bytes += request_len;
        // cur_range_conn->range_request_count++;
        rv = 1;
    }
    cur_range_conn->std_mutex.unlock();

    // if(rv <= 0 || cur_range_conn->range_request_count == cur_range_conn->erase_count){
    //     reopen_range_conn(cur_range_conn, g_remote_ip, g_remote_port, getptr());
    //     goto resend;
        if(rv <= 0){
            print_func("[Range]R%d-%d: send request failed, errno %d", cur_range_conn->id, cur_range_conn->port, errno);
            // goto resend;
        }
    // }

    return rv;
}

struct cb_range_data{
    std::shared_ptr<Optimack> obj;
    struct range_conn** range_conns;
    cb_range_data(std::shared_ptr<Optimack> obj_, struct range_conn** range_conns) : obj(obj_), range_conns(range_conns) {}
};

int cb_range_wrapper(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    // print_func("cb_range: pkt %d", nfq_get_msg_packet_hdr(nfa)->packet_id);
    struct cb_range_data* cb_data = (struct cb_range_data*)data;
    return cb_data->obj->cb_range(qh, nfmsg, nfa, (void*)(cb_data->range_conns));
}


int Optimack::cb_range(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);
    struct range_conn** range_conns = (struct range_conn**)data;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        printf("cb: can't get_msg_packet_hdr\n");
        return -1;
    }
    // int pkt_id = htonl(ph->packet_id);
    // print_func("cb_range: pkt %d", ph->packet_id);


    struct myiphdr *iphdr = ip_hdr(packet);
    struct mytcphdr *tcphdr = tcp_hdr(packet);
    unsigned char *payload = tcp_payload(packet);
    int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    unsigned short local_port = dport;
    bool incoming = true;
    if(dport == 80 || dport == 443){
        local_port = sport;
        incoming = false;
    }
    

    struct range_conn* subconn = NULL;
    for(int i = 0; i < GROUP_NUM*2; i++)
        for(int j = 0; j < RANGE_NUM;j++){
            if(range_conns[i][j].port && range_conns[i][j].port == local_port){
                subconn = &range_conns[i][j];
                break;
            }
        }
    if(!subconn){
        print_func("cb_range: conn not found");
        nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
        return -1;
    }

    short protocol = iphdr->protocol;
    if(protocol == 6){
        if(!incoming){
            switch (tcphdr->th_flags) {
                case TH_ACK:
                case TH_ACK | TH_PUSH:
                {
                    subconn->std_mutex.lock();
                    if(!subconn->in_use){
                        subconn->ini_seq_rem = ack - 1;
                        subconn->next_seq_rem = ack;
                        subconn->ini_seq_loc = seq - 1;
                        subconn->next_seq_loc = seq + payload_len;
                        subconn->in_use++;
                        print_func("R%d-%d: seq_init done - ini_seq_rem 0x%x(%u), ini_seq_loc 0x%x(%u)\n", subconn->id, local_port, subconn->ini_seq_rem, subconn->ini_seq_rem, subconn->ini_seq_loc, subconn->ini_seq_loc);
                        // setsockopt(subconn->sockfd, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK));
                        
                    }
                    subconn->std_mutex.unlock();

                    if(subconn->in_use){
                        if(payload_len && ack > subconn->next_seq_rem){
                            tcphdr->th_ack = htonl(subconn->next_seq_rem);
                            compute_checksums(packet, 20, packet_len);
                            if(debug_range) print_func("[Range]R%d-%d: change ack %x to %x", subconn->id, local_port, ack, subconn->next_seq_rem);
                        }

                    }
                    break;
                }
                default:
                    print_func("[cb_range]R%d-%d: Unknown outgoing packet flag - %d!", subconn->id, local_port, tcphdr->th_flags);
                    break;
            }
        }
        else{
            if(subconn->in_use && seq > subconn->ini_seq_rem){


                if(subconn->next_seq_loc < ack)
                    subconn->next_seq_loc = ack;
                if(subconn->next_seq_rem < seq + payload_len)
                    subconn->next_seq_rem = seq + payload_len;

                unsigned int seq_rel = seq - subconn->ini_seq_rem;
                // if(subconn->id % 100 == 0){
                //     print_func("[Range]R%d: %d -> %d <%d> seq %d(%x) ack %d(%x) ttl %u plen %d", subconn->id,  sport, dport, (tcphdr->th_flags), seq_rel, seq, ack, ack, iphdr->ttl, payload_len);
                //     nfq_set_verdict(qh, htonl(ph->packet_id), NF_DROP, packet_len, packet);
                //     return -1;
                // }

                switch (tcphdr->th_flags) {
                    case TH_ACK:
                    case TH_ACK | TH_PUSH:
                    case TH_ACK | TH_URG:
                    {
                        if(payload_len){
                            interval_map temp_range = subconn->group_recved_seq->removeInterval(seq_rel, seq_rel + payload_len);
                            // if(temp_range.size()){
                                
                            // }

                            if(temp_range.size()){
                                int group_start_i = (subconn->id/100-1);
                                for(int j = 0; j < RANGE_NUM; j++){
                                    struct range_conn* conn = &range_conns[group_start_i][j];
                                    if(conn != subconn){
                                        send_ACK_payload(g_local_ip, g_remote_ip, conn->port, 80, payload, payload_len, conn->next_seq_loc, conn->ini_seq_rem+seq_rel);
                                        // print_func("[Range]R%d-%d: [%d, %d] data sent to R%d-%d, ack %x, seq %x, %d, %s, %s", subconn->id, subconn->port, seq_rel, seq_rel + payload_len, conn->id, conn->port, conn->next_seq_loc, conn->ini_seq_rem+seq_rel, g_remote_port, g_local_ip, g_remote_ip);
                                    }
                                }
                            }
                        }
                        
                    }
                    break;
                    default:
                        print_func("[cb_range]R%d-%d: Unknown incoming packet flag - %d!",subconn->id, subconn->port, tcphdr->th_flags);
                        break;
                }
            }

        }
    }
    nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
    return 0;

}


//Multi range request
void Optimack::range_watch_multi() //void* arg
{

    memset(range_request_template, 0 , 1000);
    range_request_template_len = 0;

    struct range_conn range_conns[GROUP_NUM*2][RANGE_NUM];
    struct range_conn* range_conns_ptrs[GROUP_NUM*2];
    for(int i = 0; i < GROUP_NUM*2;i++)
        range_conns_ptrs[i] = range_conns[i];
    // struct range_conn** temp = &range_conns;
    // struct range_conn** range_conns = new struct range_conn*[GROUP_NUM];
    // for(int i = 0; i < GROUP_NUM*2; i++){
    //     // range_conns[i] = struct range_conn[RANGE_NUM];
    //     range_conns[i] = new struct range_conn[RANGE_NUM];
    //     memset(range_conns[i], 0, sizeof(struct range_conn)*RANGE_NUM);
    //     for(int j = 0; j < RANGE_NUM; j++)
    //         print_func("range_watch_multi: %d, %p", (i+1)*100+j, &range_conns[i][j]);
    // }

// #ifdef USE_NFQ
    // if(use_nfq){
    // }
// #endif

    // std::counting_semaphore<10> smphs[GROUP_NUM];

    // create array of range_conns
    std::thread open_conn_threads[GROUP_NUM];
    for(int i = 0; i < GROUP_NUM; i++){
        // open_group_range_conn(range_conns_ptrs, i, g_remote_ip, g_remote_port, getptr());
        open_conn_threads[i] = std::thread(open_group_range_conn, range_conns_ptrs, i, g_remote_ip, g_remote_port, getptr());
        open_conn_threads[i].detach();
    }

    // print_func("multi_range: sip %s, dip %s, rport %d", g_local_ip, g_remote_ip, g_remote_port);
    struct cb_range_data cb_data(getptr(), range_conns_ptrs);
    NFQ nfq_range(MARK_RANGE, (void*)&cb_data, &cb_range_wrapper);

    while(!request_len) usleep(10);

    memcpy(range_request_template, request, request_len);
    const char range_hdr[] = "Keep-Alive: timeout=150, max=300\r\nRange: bytes=";
    int range_hdr_len = strlen(range_hdr);
    sprintf(range_request_template+request_len-2, "%s", range_hdr);
    range_request_template_len = request_len - 2 + range_hdr_len;
    range_request_template[range_request_template_len] = 0;

    // for(int i = 0; i < GROUP_NUM; i++){
    //     open_conn_threads[i].join();
    //     if(!single_sender){
    //         std::thread send_worker(&Optimack::send_group_range_request_worker, getptr(), range_conns, i);
    //         send_worker.detach();
    //     }
    // }

    // char* range_str_start = range_request_template + request_len - 2 + range_hdr_len;

    // int group_cnt = 0;
    // int quotas[GROUP_NUM] = {0};
    // std::ostringstream ostr[GROUP_NUM], pstr[GROUP_NUM];
    while(!range_stop) {
        
        // for(int m = 0; m < GROUP_NUM*2; m++)
        //     print_func("open_group_range_conn: group %d, %p", (m+1), range_conns[m]);



        for(int i = 0; i < GROUP_NUM*2;i++){
                // if(quotas[i] % quota > 0)
                //     send_group_range_request_handler(getptr(), range_conns, i, ostr[i], pstr[i], quotas[i]);
                
                // if((!quotas[i] && elapsed(range_conns[i*RANGE_NUM].last_send) >= 4) || (quotas[i] && (quotas[i]/quota <= 1) && (range_job_vector.size() == 1)) ){ //send dummy requests
                double time_passed = elapsed(range_conns[i][RANGE_NUM-1].last_send);
                if(range_conns[i][RANGE_NUM-1].port && range_conns[i][0].port && (time_passed >= 4) && (time_passed < 10) && (range_conns[i][0].range_request_count <= 90)){ //send dummy requests
                    // send_group_one_range_request(range_conns[i], 1001, 1001);
                    range_conns[i][RANGE_NUM-1].last_send = std::chrono::system_clock::now();
                    std::thread send_thread(&Optimack::send_group_one_range_request, getptr(), range_conns[i], 1001, 1001);
                    send_thread.detach();
                    // ostr[i].str("1001-1001");
                    // pstr[i].str("1001-1001");
                    // send_group_range_request_handler(getptr(), range_conns, i, ostr[i], pstr[i], quotas[i]);
                }
            }
        



        // print_func("line A");

        // std::vector<uint> tmp_lost_ranges;
        // interval_set& recved_seq_intvl = recved_seq.getIntervalList();
        // if(recved_seq_intvl.end()->lower() != ranges_sent.getLastEnd()){
        //     if(processed_seq_file)    fprintf(processed_seq_file, "%f,before recved_seq, -1, -1, -1\n", get_current_epoch_time_nanosecond());
        //     pthread_mutex_lock(recved_seq.getMutex());
        //     int count = 0;
        //     uint min_next_seq_rem = get_min_next_seq_rem();
        //     for(auto prev = recved_seq_intvl.begin(), cur = next(prev); cur != recved_seq_intvl.end() && count < 2*GROUP_NUM; prev = cur, cur++, count++){ //
        //         if(cur->lower()-1 < min_next_seq_rem) {
        //             tmp_lost_ranges.push_back(prev->upper());
        //             tmp_lost_ranges.push_back(cur->lower()-1);
        //         }
        //     }
        //     pthread_mutex_unlock(recved_seq.getMutex());
        //     if(processed_seq_file)    fprintf(processed_seq_file, "%f,after recved_seq, -1, -1, -1\n", get_current_epoch_time_nanosecond());

        //     for(int i = 0; i < tmp_lost_ranges.size(); i += 2){
        //         insert_lost_range(tmp_lost_ranges.at(i), tmp_lost_ranges.at(i+1));
        //     }
        // //    if(processed_seq_file)    fprintf(processed_seq_file, "%f,after , -1, -1\n", get_current_epoch_time_nanosecond());
        // }

            // print_func("line 493");
            // for(int i = 0; i < GROUP_NUM;i++){
            //     struct range_conn* cur_range_conn = &range_conns[i*RANGE_NUM];
            //     if(elapsed(cur_range_conn->last_send) >= 4){
            //         ostr[i].str("100001-100001");
            //         pstr[i].str("100001-100001");
            //         send_group_range_request_handler(getptr(), range_conns, i, ostr[i], pstr[i], quotas[i]);
            // //         for(int j = 0; j < RANGE_NUM; j++){
            // //             std::thread reopen_range_conn_thread(reopen_range_conn, &range_conns[i*RANGE_NUM+j], g_remote_ip, g_remote_port, getptr());
            // //             reopen_range_conn_thread.detach();
            // //         }
            //     }
            // }
            // usleep(10);
            // continue;

        // print_func("line B");
        // int quota = (size + GROUP_NUM - 1) / GROUP_NUM;
        // const int QUOTA = 4;
        // // print_func("[Range]: size %d, quota %d", size, quota);
        // if (quota < 1)
        //     quota = 1;
        // else if (quota > QUOTA)
        //     quota = QUOTA;

        // //find next available range
        // auto it = range_job_vector.begin(); 
        // while(range_job_vector.size() != 0 && it != range_job_vector.end()){
        //     // print_func("line C");
        //     if (cur_ack_rel >= it->end){
        //         if(debug_range){ log_info("[Range] cur_ack_rel %u >= it->end %u, delete\n", cur_ack_rel, it->end); } //print_func("[Range] cur_ack_rel %u >= it->end %u, delete, erase count %d", cur_ack_rel, end_tcp_seq, erase_count); }
        //         pthread_mutex_lock(&mutex_range);
        //         it = range_job_vector.erase(it);
        //         pthread_mutex_unlock(&mutex_range);
        //         continue;
        //     }
        //     double current_time = get_current_epoch_time_nanosecond();
        //     if(!it->sent_epoch_time || (current_time - it->sent_epoch_time >= 4)){
        //         // print_func("line C1");
        //         int group_i = (group_cnt++) % GROUP_NUM;
        //         if(it->sent_epoch_time){
        //             print_func("[Range]: [%u, %u] timeout", it->start, it->end);
        //             if(processed_seq_file)  fprintf(processed_seq_file, "%f,request timeout,%d,%u,%u\n", current_time, (group_i+1)*100, it->start,it->end+1);
        //         }
        //         it->sent_epoch_time = current_time;

        //         if(quotas[group_i]++ % quota > 0){
        //             ostr[group_i] << ", ";
        //             pstr[group_i] << ", ";
        //         }
        //         ostr[group_i] << get_byte_seq(it->start) << "-" << get_byte_seq(it->end);
        //         pstr[group_i] << it->start << "-" << it->end;                
        //         if(processed_seq_file)  fprintf(processed_seq_file, "%f,request,%d,%u,%u\n", current_time, (group_i+1)*100, it->start,it->end+1);
        //         // print_func("[Range]: found %u-%u, ostr %s", it->start, it->end, ostr.str().c_str());

        //         // print_func("R%d: size %u,  quotas[] %d / quota %d, [%u, %u]", group_i, range_job_vector.size(), quotas[group_i], quota, it->start, it->end+1);
        //         if(quotas[group_i] >= quota && quotas[group_i] % quota == 0){
        //             send_group_range_request_handler(getptr(), range_conns, group_i, ostr[group_i], pstr[group_i], quotas[group_i]);
        //         }
        //     }
        //     it++;
        // }
        // print_func("line D");
        //send unfinished quotas
        

        usleep(500);
    }

    // delete[] range_conns;
    // for(int i = 0; i )
    print_func("[Range]: range_watch_multi thread exits...\n");
    // pthread_exit(NULL);
    return;
}



 
int Optimack::send_http_range_request(struct range_conn* cur_range_conn){
    char ranges_str[1000] = {0};
    uint* ranges_tmp = cur_range_conn->ranges;
    for(int i = 0; ranges_tmp[i] && i < 10; i += 2){
        if(i > 1)
            strncat(ranges_str, ", ", 2);
        snprintf(ranges_str, 1000, "%s%u-%u", ranges_str, ranges_tmp[i], ranges_tmp[i+1]);
    }
    print_func("[Range]R%d-%d: multi-range %s", cur_range_conn->id, cur_range_conn->port, ranges_str);

    return send_http_range_request(cur_range_conn, ranges_str);
}


int Optimack::send_http_range_request(struct range_conn* cur_range_conn, Interval* range){
    uint start = get_byte_seq(range->start), end = get_byte_seq(range->end);
    if (start == end || (start == 0 || end == 0 || request == NULL || request_len == 0))
        return -1;
    
    char ranges_str[100] = {0};
    snprintf(ranges_str, 100, "%d-%d", start, end);
    return send_http_range_request(cur_range_conn, ranges_str);
}


int find_least_range_conn(struct range_conn* range_conns, int range_conn_num){
    int min_i = 0;
    for(int i = 0; i < range_conn_num; i++){
        if(range_conns[i].requested_bytes < range_conns[min_i].requested_bytes){
            min_i = i;
        }
    }
    return min_i;
}



int Optimack::range_worker(int& sockfd, Interval* it){
    while(true){
        if(it->end <= cur_ack_rel)
            break;

        int rv = send_http_range_request((void*)sockfd, it);

        if (rv < 0){
            print_func("[Range]: R%d bytes [%u, %u] failed\n", sockfd, it->start, it->end);
            log_debug("[R%d] bytes %d - %d failed", sockfd, it->start, it->end);
            // it->sent_epoch_time = 0;
        } 
        else{
            if(debug_range) print_func("[Range]: R%d bytes %d[%u, %u] requested", sockfd, rv, it->start, it->end);
            int ret = range_recv_block(sockfd, it);
            if(ret >= 0)
                break;
        }

        sockfd = establish_tcp_connection(sockfd, g_remote_ip, g_remote_port);
    }
    it->last_recved--;
    if(it->last_recved == 0)
        delete it;
    return 0;
}


int Optimack::range_recv_block(int sockfd, Interval* it){
    char response[MAX_RANGE_SIZE+1];
    int rv = 0, sockfd_old = 0;
    http_header header;
    header.start = (it->start);
    header.end = (it->end);
    header.parsed = 0;
    header.remain = it->end - it->start + 1;
    header.recved = 0;
    subconn_info* subconn = (subconn_infos.begin()->second);

    int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0, packet_len=0;
    while (header.remain != 0){
        if(recv_offset == 0)
            memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset+1);
        if(is_ssl){
    #ifdef USE_OPENSSL
            // rv = SSL_read(range_conn_this->ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
    #endif
        }
        else{
            // print_func("[Range]: R%d, before recv", sockfd);
            rv = recv(sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);
        }

        if (rv > 0) {
            if(debug_range){
                log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
                print_func("[Range]: R%d recved %d bytes, hand over to process_range_rv", sockfd, rv);
            }
            process_range_rv_old(response, rv, this, subconn, &header, consumed, unread, parsed, recv_offset, unsent);
        }
        else if(rv <= 0){
            if(rv == 0){
                if(debug_range){
                    log_debug("[Range] recv ret %d, sockfd %d closed ", rv, sockfd);
                    print_func("[Range] recv ret %d, sockfd %d closed\n", rv, sockfd);
                }
            }
            else{
                // log_debug("[Range] R%d ret %d errno %d", rv, errno);
                // print_func("[Range] R%d ret %d errno %d\n", sockfd, rv, errno);
                if(!is_ssl){
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK){
                        continue;
                    }
                }
            }
            cleanup_range(sockfd, sockfd_old, &header, consumed, unread, parsed, recv_offset, unsent);
            if(debug_range) print_func("[Range]: closed range_sockfd %d\n", sockfd);
    #ifdef USE_OPENSSL
            // if(is_ssl)
                // range_conn_this->ssl_old = range_conn_this->ssl;
    #endif
            return -1;
        }
        usleep(100);
    }
    return 0;
}



int process_range_rv_old(char* response, int rv, Optimack* obj, subconn_info* subconn, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
//     if (rv > MAX_RANGE_SIZE)
//         print_func("[Range]: rv %d > MAX %d\n", rv, MAX_RANGE_SIZE);

//     // char data[MAX_RANGE_SIZE+1];
//     unread += rv;
//     consumed = 0;
//     while (unread > 0) {
//         if (!header->parsed) {
//             // parse header
//             parsed = parse_response(header, response+consumed, unread);
//             if (parsed <= 0) {
//                 // incomplete http header
//                 // keep receiving and parse in next response
//                 memmove(response, response+consumed, unread);
//                 recv_offset += unread;
//                 log_error("[Range] incomplete http header, len %d\n", unread);
//                 print_func("[Range] incomplete http header, len %d\n", unread);
//                 break;
//             }
//             else {
//                 recv_offset = 0;
//                 consumed += parsed;
//                 unread -= parsed;
//             }
//         }
//         else {
//             if(header->end > obj->cur_ack_rel){
//                 if(debug_range){
//                     print_func("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
//                     // log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
//                 }
//                 // obj->ranges_sent.removeInterval_updateTimer(header->start+header->recved, header->start+header->recved+unread);

//                 int seq_rel = header->start + header->recved;
//                 unsigned char* send_data = (u_char*)(response + consumed);
//                 obj->store_and_send_data(seq_rel, send_data, unread, NULL, true, );
//             }
//             header->recved += unread;
//             header->remain -= unread;
//             consumed += unread;
//             unread -= unread;

//             recv_offset = unread;
//             memcpy(response, response+consumed, unread);
//             // header->start += sent;
//             break;
//         }
//     }

//     if(unread == 0 && header->remain == 0)
//         header->parsed = 0;

//     if (unread < 0){
//         log_debug("[Range] error: unread < 0");
//         return -1;
//     }
//     if(recv_offset >= MAX_RANGE_SIZE){
//         print_func("recv_offset %d > MAX_RANGE_SIZE %u\n", recv_offset, MAX_RANGE_SIZE);
//         return -1;
//     }
//     return 0;
}


int Optimack::insert_lost_range(uint start, uint end)
{
    // uint start = get_byte_seq(start_), end = get_byte_seq(end_);
    if(start == -1 || end == -1)
        return -1;
    

    // check if the range has already been sent
    // IntervalListWithTime lost_range;
    // lost_range.clear();
    // lost_range.insertNewInterval(start, end);
    // ranges_sent.lock();
    // lost_range.substract(&ranges_sent);
    // ranges_sent.unlock();
    
    // // print_func("insert_lost_range: try [%u, %u], result [%u, %u]", start_)
    // if(lost_range.size()){
    //     // print_func("[Range]: get lost range, tcp_seq[%u, %u], byte_seq[%u, %u], tcp_seq[%u, %u]\n", intvl->start, intvl->end, start, end, get_tcp_seq(start), get_tcp_seq(end));
    //     for(auto intvl : lost_range.getIntervalList()){
            
    //         for(int st = intvl.start; st < intvl.end; st += 2*squid_MSS){
    //             int ed = st + 2*squid_MSS < intvl.end? st + 2*squid_MSS : intvl.end;
    //             ranges_sent.insertNewInterval_withLock(st, ed);
    //             if(processed_seq_file)  fprintf(processed_seq_file, "%f,detect,%d,%u,%u\n", get_current_epoch_time_nanosecond(), -1, st, ed+1);
    //         }

    //         // ranges_sent.insertNewInterval_withLock(intvl);
    //         // if(processed_seq_file)  fprintf(processed_seq_file, "%f,detect,%d,%u,%u\n", get_current_epoch_time_nanosecond(), -1, intvl.start, intvl.end);
    //     }

// #ifdef USE_OPENSSL
//         if(is_ssl)
//             if((end != ack_end) && (end - start + 1) % MAX_FRAG_LEN != 0){
//                 print_func("get_lost_range: len(%u) mod %d != 0\n", end-start+1, MAX_FRAG_LEN);
//                 // return -1;
//                 // uint recordnum = (intvl->end - intvl->start + 1) / MAX_FRAG_LEN + 1;
//                 // intvl->end = intvl->start + MAX_FRAG_LEN * recordnum - 1;
//                 // print_func("change range to [%u, %u]\n", intvl->start, intvl->end);
//                 recved_seq.printIntervals();
//             }
// #endif
//         return 0;
//     }
//     else
//         return -1;
}
/***
   *tcp_seq: 1 <-tlshdr5-> 6 <-iv8-> 14 <-plaintext512-> 526 <-tag16-> 542 <-tlshdr5-> 547 <-iv8-> 555 <-plaintext512-> 1067 <-tag16-> 1083
   *byte seq(w_response_header):      1 <-plaintext512->                                           513 <-plaintext512->
   *tcp_seq,     byte_seq
   *1(start),    1         1 = 1 - 1/541*(5+8+16)
   *541(end),    512       512 = 541 - 541/541*29
   *542(start),  513       513 = 542 - 542/541*29
   *1082(end),   1024      1024 = 1082 - 1082/541*29
***/
uint Optimack::get_byte_seq(uint tcp_seq){

    if(!response_header_len)
        return -1;

    long tcp_seq_sign = tcp_seq;

#ifdef USE_OPENSSL
    // uint record_num = get_record_num(tcp_seq);
    if(is_ssl)
        tcp_seq_sign -= tcp_seq_sign / MAX_FULL_GCM_RECORD_LEN * (TLSHDR_SIZE + 8 + 16);
#endif

    tcp_seq_sign -= response_header_len + 1; // range starts from zero!

    if(tcp_seq_sign < 0)
        return -1;
    return tcp_seq_sign;
}


uint Optimack::get_tcp_seq(uint byte_seq){

    byte_seq += response_header_len + 1;

#ifdef USE_OPENSSL
    if(is_ssl){
        if((byte_seq)%MAX_FRAG_LEN != 0){
            // print_func("get_tcp_seq: Not full divide: seq(%u %x) mod record_full_size(%d)\n", byte_seq, byte_seq, MAX_FRAG_LEN);
            log_info("get_tcp_seq: Not full divide: seq(%u %x) mod record_full_size(%d)\n", byte_seq, byte_seq, MAX_FRAG_LEN);
        }
        byte_seq += (byte_seq) / MAX_FRAG_LEN * (TLSHDR_SIZE + 8 + 16);
    }
#endif

    return byte_seq;
}




int Optimack::send_http_range_request(void* sockfd, Interval* range){
    uint start = get_byte_seq(range->start), end = get_byte_seq(range->end);
    if (start == end || (start == 0 || end == 0 || request == NULL || request_len == 0))
        return -1;
    
    char* range_request = (char *)malloc(request_len+100);
    memset(range_request, 0 , request_len+100);
    memcpy(range_request, request, request_len);
    sprintf(range_request+request_len-2, "Keep-Alive: timeout=150, max=300\r\nRange: bytes=%u-%u\r\n\r\n", start, end);

    int rv = -1;
    if(is_ssl){
#ifdef USE_OPENSSL
        SSL *ssl = (SSL *)sockfd;
        if(ssl)
            rv = SSL_write(ssl, range_request, strlen(range_request));
#endif
    }
    else{
        int sockfd_ = (long)sockfd;
        rv = send(sockfd_, range_request, strlen(range_request), 0);
        // for(int i = range->start; i+squid_MSS < range->end; i += squid_MSS){
        //     double ct = get_current_epoch_time_nanosecond();
        //     fprintf(forward_seq_file, "%f, %u\n", ct, i);
        // }

    }
    free(range_request);
    return rv;
}


void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    close(range_sockfd);
    range_sockfd_old = range_sockfd;
    range_sockfd = -1;
    memset(header, 0, sizeof(http_header));
    consumed = unread = parsed = recv_offset = unsent = 0;
}

int Optimack::get_http_response_header_len(subconn_info* subconn, unsigned char* payload, int payload_len){
#ifndef GPROF_CHECK
    Http1::ResponseParser rp;
    SBuf headerBuf;
    pthread_mutex_lock(&mutex_range);
    headerBuf.assign((char*)payload, payload_len);
    rp.parse(headerBuf);
    response_header_len = rp.messageHeaderSize();
    pthread_mutex_unlock(&mutex_range);
#else
    response_header_len = 398;
#endif

    response = (char*)malloc(response_header_len+1);
    memcpy(response, payload, response_header_len);
    response[response_header_len] = 0;

    // const char* content_len_field = "Content-Length: ";
    // char* payload_end = (char*)payload + payload_len;
    // int content_len_field_len = strlen(content_len_field);
    // char* p_content_len = std::search((char*)payload, (char*)payload+payload_len, content_len_field, content_len_field+content_len_field_len);
    
    // p_content_len += content_len_field_len;
    file_size = get_content_length((char*)payload, payload_len);
    if(file_size){
        if(is_ssl){
#ifdef USE_OPENSSL
            ack_end = ((file_size + response_header_len - 1)/MAX_FRAG_LEN + 1) * MAX_FULL_GCM_RECORD_LEN + 1;
#endif
        }
        else
            ack_end += file_size + response_header_len;
    }
    // else
    // ack_end = 1;
    // print_func("S%d-%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn->id, subconn->local_port, response_header_len, rp.parseStatusCode, file_size, ack_end);
    // log_info("S%d-%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn->id, subconn->local_port, response_header_len, rp.parseStatusCode, file_size, ack_end);
    // print_func("seq in this conn-%u, file byte-%u, %c\n", seq_rel+response_header_len, 0, payload[response_header_len+1]);
    // src/http/StatusCode.h
    return 0;
}

int get_content_length(const char* payload, int payload_len){
    const char* contentlen_field = "Content-Length: ";
    const char* payload_end = payload + payload_len;
    int contentlen_field_len = strlen(contentlen_field);
    const char* p_contentlen = std::search(payload, payload+payload_len, contentlen_field, contentlen_field+contentlen_field_len);
    if(p_contentlen < payload_end){
        p_contentlen += contentlen_field_len;
        int file_size = (u_int)std::stol(p_contentlen);
        return file_size;
    }
    return -1;
}


/*
 * Thread pool implementation.
 * See <thr_pool.h> for interface declarations.
 */

static sigset_t fillset;

/* the list of all created and not yet destroyed thread pools */
static thr_pool_t *thr_pools = NULL;

/* protects thr_pools */
static pthread_mutex_t thr_pool_lock = PTHREAD_MUTEX_INITIALIZER;

static void *worker_thread(void *);


int establish_tcp_connection(int old_sockfd, int remote_ip, unsigned short remote_port)
{
    int sockfd = 0;
    struct sockaddr_in server_addr;

    // Open socket
opensocket:
    while(sockfd == 0 || sockfd == old_sockfd){ //
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Can't open stream socket.");
            return -1;
        }
        if(debug_range) printf("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = remote_ip;
    server_addr.sin_port = htons(remote_port);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Connect to server
    int count = 0;
    while (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 && count++ < 5) {
        printf("establish_tcp_connection: sockfd %d connect error\n", sockfd);
        perror("Connect server error");
    }

    if(count >= 5){
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }

    // int port = get_localport(sockfd);
    // if(port < 0){
    //     printf("establish_tcp_connection: sockfd %d get_localport error\n", sockfd);
    //     sockfd = 0;
    //     close(sockfd);
    //     goto opensocket;
    // }

    if(debug_range) printf("establish_tcp_connection: connect sockfd %d\n", sockfd);

    return sockfd;
}





static int
create_worker(thr_pool_t *pool)
{
    pthread_t threads;
    sigset_t oset;
    int error;

    (void) pthread_sigmask(SIG_SETMASK, &fillset, &oset);
    error = pthread_create(&threads, &pool->pool_attr, worker_thread, pool);
    (void) pthread_sigmask(SIG_SETMASK, &oset, NULL);
    return (error);
}

/*
 * Worker thread is terminating.  Possible reasons:
 * - excess idle thread is terminating because there is no work.
 * - thread was cancelled (pool is being destroyed).
 * - the job function called pthread_exit().
 * In the last case, create another worker thread
 * if necessary to keep the pool populated.
 */
static void
worker_cleanup(void *arg)
// worker_cleanup(thr_pool_t *pool)
{
    thr_pool_t *pool = (thr_pool_t *)arg;
    --pool->pool_nthreads;
    if (pool->pool_flags & POOL_DESTROY) {
        if (pool->pool_nthreads == 0)
            (void) pthread_cond_broadcast(&pool->pool_busycv);
    } else if (pool->pool_head != NULL &&
        pool->pool_nthreads < pool->pool_maximum &&
        create_worker(pool) == 0) {
        pool->pool_nthreads++;
    }
    (void) pthread_mutex_unlock(&pool->pool_mutex);
}

static void
notify_waiters(thr_pool_t *pool)
{
    if (pool->pool_head == NULL && pool->pool_active == NULL) {
        pool->pool_flags &= ~POOL_WAIT;
        (void) pthread_cond_broadcast(&pool->pool_waitcv);
    }
}

/*
 * Called by a worker thread on return from a job.
 */
static void
job_cleanup(void *arg)
{
    thr_pool_t *pool = (thr_pool_t *)arg;
    pthread_t my_tid = pthread_self();
    active_t *activep;
    active_t **activepp;

    (void) pthread_mutex_lock(&pool->pool_mutex);
    for (activepp = &pool->pool_active;
        (activep = *activepp) != NULL;
        activepp = &activep->active_next) {
        if (activep->active_tid == my_tid) {
            *activepp = activep->active_next;
            break;
        }
    }
    if (pool->pool_flags & POOL_WAIT)
        notify_waiters(pool);
}

static void *
worker_thread(void *arg)
{
    thr_pool_t *pool = (thr_pool_t *)arg;
    int timedout;
    job_t *job;
    void *(*func)(void *);
    active_t active;
    struct timespec ts;

    int count = 0;
    Optimack* obj = (Optimack*)pool->obj;
    pthread_cond_t& cur_workcv = pool->pool_workcvs[pool->last_worker];
    // pthread_mutex_t cur_mutex;
    // (void) pthread_mutex_init(&cur_mutex, NULL);
    pool->last_worker = (pool->last_worker + 1) % pool->pool_maximum;
    int sockfd = establish_tcp_connection(0, obj->g_remote_ip_int, obj->g_remote_port);
    if(debug_range) printf("worker_thread: this is fd %d\n", sockfd);
    // int port = get_localport(sockfd);
    // if(port > 0){
    //     fprintf(obj->processed_seq_file, "%d ", port);
    //     printf("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);
    // }

    /*
     * This is the worker's main loop.  It will only be left
     * if a timeout occurs or if the pool is being destroyed.
     */
    (void) pthread_mutex_lock(&pool->pool_mutex);
    pthread_cleanup_push(&worker_cleanup, (void *)pool);
    active.active_tid = pthread_self();
    for (;;) {
        /*
         * We don't know what this thread was doing during
         * its last job, so we reset its signal mask and
         * cancellation state back to the initial values.
         */
        (void) pthread_sigmask(SIG_SETMASK, &fillset, NULL);
        (void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        (void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

        timedout = 0;
        pool->pool_idle++;
        if (pool->pool_flags & POOL_WAIT)
            notify_waiters(pool);
        while (pool->pool_head == NULL &&
            !(pool->pool_flags & POOL_DESTROY)) {
            if (pool->pool_nthreads <= pool->pool_minimum) {
                (void) pthread_cond_wait(&cur_workcv,
                    &pool->pool_mutex);
            } else {
                (void) clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += pool->pool_linger;
                if (pool->pool_linger == 0 ||
                    pthread_cond_timedwait(&cur_workcv,
                    &pool->pool_mutex, &ts) == ETIMEDOUT) {
                    timedout = 1;
                    break;
                }
            }
        }
        pool->pool_idle--;
        if (pool->pool_flags & POOL_DESTROY)
            break;
        if ((job = pool->pool_head) != NULL) {
            timedout = 0;
            func = job->job_func;
            arg = job->job_arg;
            pool->pool_head = job->job_next;
            if (job == pool->pool_tail)
                pool->pool_tail = NULL;
            active.active_next = pool->pool_active;
            pool->pool_active = &active;
            (void) pthread_mutex_unlock(&pool->pool_mutex);
            pthread_cleanup_push(&job_cleanup, (void *)pool);
            free(job);
            /*
             * Call the specified job function.
             */
            obj->range_worker(sockfd, (Interval*)arg);
            if(count++ > 90){
                sockfd = establish_tcp_connection(sockfd, obj->g_remote_ip_int, obj->g_remote_port);
                // port = get_localport(sockfd);
                // if(port > 0){
                //     fprintf(obj->processed_seq_file, "%d ", port);
                //     printf("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);
                // }
                count = 0;
            }

            /*
             * If the job function calls pthread_exit(), the thread
             * calls job_cleanup(pool) and worker_cleanup(pool);
             * the integrity of the pool is thereby maintained.
             */
            pthread_cleanup_pop(1);    /* job_cleanup(pool) */
        }
        if (timedout && pool->pool_nthreads > pool->pool_minimum) {
            /*
             * We timed out and there is no work to be done
             * and the number of workers exceeds the minimum.
             * Exit now to reduce the size of the pool.
             */
            break;
        }
    }
    pthread_cleanup_pop(1);    /* worker_cleanup(pool) */
    return (NULL);
}

static void
clone_attributes(pthread_attr_t *new_attr, pthread_attr_t *old_attr)
{
    struct sched_param param;
    void *addr;
    size_t size;
    int value;

    (void) pthread_attr_init(new_attr);

    if (old_attr != NULL) {
        (void) pthread_attr_getstack(old_attr, &addr, &size);
        /* don't allow a non-NULL thread stack address */
        (void) pthread_attr_setstack(new_attr, NULL, size);

        (void) pthread_attr_getscope(old_attr, &value);
        (void) pthread_attr_setscope(new_attr, value);

        (void) pthread_attr_getinheritsched(old_attr, &value);
        (void) pthread_attr_setinheritsched(new_attr, value);

        (void) pthread_attr_getschedpolicy(old_attr, &value);
        (void) pthread_attr_setschedpolicy(new_attr, value);

        (void) pthread_attr_getschedparam(old_attr, &param);
        (void) pthread_attr_setschedparam(new_attr, &param);

        (void) pthread_attr_getguardsize(old_attr, &size);
        (void) pthread_attr_setguardsize(new_attr, size);
    }

    /* make all pool threads be detached threads */
    (void) pthread_attr_setdetachstate(new_attr, PTHREAD_CREATE_DETACHED);
}

thr_pool_t *
thr_pool_create_range(uint_t min_threads, uint_t max_threads, uint_t linger,
    pthread_attr_t *attr, Optimack* obj)
{
    thr_pool_t    *pool;

    (void) sigfillset(&fillset);

    if (min_threads > max_threads || max_threads < 1) {
        errno = EINVAL;
        return (NULL);
    }

    if (((pool = (thr_pool_t *) malloc(sizeof (*pool))) == NULL)) {
        errno = ENOMEM;
        return (NULL);
    }
    (void) pthread_mutex_init(&pool->pool_mutex, NULL);
    (void) pthread_cond_init(&pool->pool_busycv, NULL);
    (void) pthread_cond_init(&pool->pool_workcv, NULL);
    (void) pthread_cond_init(&pool->pool_waitcv, NULL);
    pool->pool_active = NULL;
    pool->pool_head = NULL;
    pool->pool_tail = NULL;
    pool->pool_flags = 0;
    pool->pool_linger = linger;
    pool->pool_minimum = min_threads;
    pool->pool_maximum = max_threads;
    pool->pool_nthreads = 0;
    pool->pool_idle = 0;

    pool->pool_workcvs = new pthread_cond_t[max_threads];
    for(int i = 0; i < max_threads; i++)
    (void) pthread_cond_init(&pool->pool_workcvs[i], NULL); 
    pool->last_worker = 0;
    pool->obj = (void*)obj;

    /*
     * We cannot just copy the attribute pointer.
     * We need to initialize a new pthread_attr_t structure using
     * the values from the caller-supplied attribute structure.
     * If the attribute pointer is NULL, we need to initialize
     * the new pthread_attr_t structure with default values.
     */
    clone_attributes(&pool->pool_attr, attr);

    /* insert into the global list of all thread pools */
    (void) pthread_mutex_lock(&thr_pool_lock);
    if (thr_pools == NULL) {
        pool->pool_forw = pool;
        pool->pool_back = pool;
        thr_pools = pool;
    } else {
        thr_pools->pool_back->pool_forw = pool;
        pool->pool_forw = thr_pools;
        pool->pool_back = thr_pools->pool_back;
        thr_pools->pool_back = pool;
    }
    (void) pthread_mutex_unlock(&thr_pool_lock);

    for(;pool->pool_nthreads < pool->pool_maximum; pool->pool_nthreads++)
        create_worker(pool);
        
    return (pool);
}

int
thr_pool_queue_range(thr_pool_t *pool, void *arg)
{
    job_t *job;

    if ((job = (job_t *) malloc(sizeof (*job))) == NULL) {
        errno = ENOMEM;
        return (-1);
    }
    job->job_next = NULL;
    // job->job_func = func;
    job->job_arg = arg;

    (void) pthread_mutex_lock(&pool->pool_mutex);

    if (pool->pool_head == NULL)
        pool->pool_head = job;
    else
        pool->pool_tail->job_next = job;
    pool->pool_tail = job;

    (void) pthread_mutex_unlock(&pool->pool_mutex);

    if (pool->pool_idle > 0){
        for(int i = 0; i < RANGE_NUM; i++){
            (void) pthread_cond_signal(&pool->pool_workcvs[pool->last_worker++]);	
            pool->last_worker %= pool->pool_nthreads;
        }

    }
    

    return (0);
}

void
thr_pool_wait_range(thr_pool_t *pool)
{
    (void) pthread_mutex_lock(&pool->pool_mutex);
    pthread_cleanup_push((void (*)(void*))&pthread_mutex_unlock, &pool->pool_mutex);
    while (pool->pool_head != NULL || pool->pool_active != NULL) {
        pool->pool_flags |= POOL_WAIT;
        (void) pthread_cond_wait(&pool->pool_waitcv, &pool->pool_mutex);
    }
    pthread_cleanup_pop(1);    /* pthread_mutex_unlock(&pool->pool_mutex); */
}

void
thr_pool_destroy_range(thr_pool_t *pool)
{
    active_t *activep;
    job_t *job;

    (void) pthread_mutex_lock(&pool->pool_mutex);
    pthread_cleanup_push((void (*)(void*))&pthread_mutex_unlock, &pool->pool_mutex);

    /* mark the pool as being destroyed; wakeup idle workers */
    pool->pool_flags |= POOL_DESTROY;
    (void) pthread_cond_broadcast(&pool->pool_workcv);

    /* cancel all active workers */
    for (activep = pool->pool_active;
        activep != NULL;
        activep = activep->active_next)
        (void) pthread_cancel(activep->active_tid);

    /* wait for all active workers to finish */
    while (pool->pool_active != NULL) {
        pool->pool_flags |= POOL_WAIT;
        (void) pthread_cond_wait(&pool->pool_waitcv, &pool->pool_mutex);
    }

    /* the last worker to terminate will wake us up */
    while (pool->pool_nthreads != 0)
        (void) pthread_cond_wait(&pool->pool_busycv, &pool->pool_mutex);

    pthread_cleanup_pop(1);    /* pthread_mutex_unlock(&pool->pool_mutex); */

    /*
     * Unlink the pool from the global list of all pools.
     */
    (void) pthread_mutex_lock(&thr_pool_lock);
    if (thr_pools == pool)
        thr_pools = pool->pool_forw;
    if (thr_pools == pool)
        thr_pools = NULL;
    else {
        pool->pool_back->pool_forw = pool->pool_forw;
        pool->pool_forw->pool_back = pool->pool_back;
    }
    (void) pthread_mutex_unlock(&thr_pool_lock);

    /*
     * There should be no pending jobs, but just in case...
     */
    for (job = pool->pool_head; job != NULL; job = pool->pool_head) {
        pool->pool_head = job->job_next;
        free(job);
    }
    (void) pthread_attr_destroy(&pool->pool_attr);
    free(pool);
}


int Optimack::check_range_conn(struct range_conn* range_conn_this, std::vector<Interval>& range_job_vector){
    if(range_conn_this->sockfd <= 0 || range_conn_this->range_request_count >= 95 || range_conn_this->erase_count >= 5){
    
        //clear all sent timestamp, to resend it
        // pthread_mutex_lock(p_mutex_range_job_vector);
restart:
        for (auto it = range_job_vector.begin(); it != range_job_vector.end();it++){
            it->sent_epoch_time = 0;
        }
        // pthread_mutex_unlock(p_mutex_range_job_vector);

        range_conn_this->sockfd = establish_tcp_connection(range_conn_this->sockfd_old, g_remote_ip, g_remote_port);
        close(range_conn_this->sockfd_old);
        // print_func("[Range] New conn, fd %d, port %d\n", range_conn_this->sockfd, get_localport(range_conn_this->sockfd));
        log_info("[Range] New conn, fd %d, port %d\n", range_conn_this->sockfd, get_localport(range_conn_this->sockfd));
        if(is_ssl){
    #ifdef USE_OPENSSL
            range_conn_this->ssl = NULL;
            range_conn_this->ssl = open_ssl_conn(range_conn_this->sockfd, false);
            if(range_conn_this->ssl_old)
                SSL_free(range_conn_this->ssl_old);
            if(!range_conn_this->ssl){
                sleep(1);
                goto restart;
            }
            fcntl(range_conn_this->sockfd, F_SETFL, O_NONBLOCK);
    #endif
        }
        range_conn_this->range_request_count = 0;
        range_conn_this->erase_count = 0;
        if(range_conn_this->sockfd <= 0){ //TODO: remove ranges_sent?{
            perror("Can't create range_sockfd, range thread break\n");
            return -1;
        }
    }
}



void
Optimack::range_watch() //void* arg
{
//     // pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

//     // print_func("[Range]: range_watch thread starts, ref_count %d\n", getptr().use_count());

// #ifdef USE_OPENSSL
//     SSL *range_ssl, *range_ssl_old;
// #endif

//     int rv, range_sockfd, range_sockfd_old, erase_count = 0;
//     char response[MAX_RANGE_SIZE+1];

//     // Optimack* obj = ((Optimack*)arg);
//     // std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared_copy = obj->subconn_infos_shared;

//     range_sockfd = -1;

//     pthread_mutex_t *mutex = &(mutex_seq_gaps);
//     subconn_info* subconn = (subconn_infos.begin()->second);

//     std::vector<Interval>& range_job_vector = ranges_sent.getIntervalList();
//     pthread_mutex_t* p_mutex_range_job_vector = ranges_sent.getMutex();

//     int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0, packet_len=0;
//     http_header* header = (http_header*)malloc(sizeof(http_header));
//     memset(header, 0, sizeof(http_header));
//     // parser
//     // Http1::RequestParser rp;
//     // SBuf headerBuf;

//     // int fd = open("/dev/null", O_RDONLY);
//     // dup2(fd, STDIN_FILENO);
//     // close(fd);
//     // for(int fd=0; fd < 3; fd++){
//     //     int nfd;
//     //     nfd = open("/dev/null", O_RDWR);

//     //     if(nfd<0) /* We're screwed. */
//     //     continue;

//     //     if(nfd==fd)
//     //     continue;

//     //     dup2(nfd, fd);
//     //     if(nfd > 2)
//     //     close(nfd);
//     // }

//     while(!range_stop) {

//         try_for_gaps_and_request();

//         if(range_job_vector.size() == 0){
//             // print_func("range_job_vector.size() == 0\n");
//             continue;
//         }

//         if(range_sockfd <= 0 || range_request_count >= 95 || erase_count >= 5){
//             //clear all sent timestamp, to resend it
//             // pthread_mutex_lock(p_mutex_range_job_vector);
// restart:
//             for (auto it = range_job_vector.begin(); it != range_job_vector.end();it++){
//                 it->sent_epoch_time = 0;
//             }
//             // pthread_mutex_unlock(p_mutex_range_job_vector);

//             range_sockfd = establish_tcp_connection(range_sockfd_old, g_remote_ip, g_remote_port);
//             close(range_sockfd_old);
//             range_sockfd_old = range_sockfd;
//             // print_func("[Range] New conn, fd %d, port %d\n", range_sockfd, get_localport(range_sockfd));
//             // log_info("[Range] New conn, fd %d, port %d\n", range_sockfd, get_localport(range_sockfd));
//             if(is_ssl){
// #ifdef USE_OPENSSL
//                 range_ssl = NULL;
//                 range_ssl = open_ssl_conn(range_sockfd, false);
//                 if(range_ssl_old)
//                     SSL_free(range_ssl_old);
//                 if(!range_ssl){
//                     sleep(1);
//                     goto restart;
//                 }
//                 fcntl(range_sockfd, F_SETFL, O_NONBLOCK);
// #endif
//             }
//             range_request_count = 0;
//             erase_count = 0;
//         }
//         if(range_sockfd <= 0){ //TODO: remove ranges_sent?{
//             perror("Can't create range_sockfd, range thread break\n");
//             break;
//         }

//         //Check if any more unsent range and sent
//         // print_func("Check if any more unsent range and sent\n");
//         // pthread_mutex_lock(p_mutex_range_job_vector);
//         for (auto it = range_job_vector.begin(); it != range_job_vector.end();){
//         // for(auto it : range_job->getIntervalList()) {
//             // print_func("[Range] Resend bytes %d - %d\n", it.start, it.end);
//             uint end_tcp_seq = get_tcp_seq(it->end);
//             if (cur_ack_rel >= end_tcp_seq){
//                 erase_count++;
//                 log_info("[Range] cur_ack_rel %u >= it->end %u, delete\n", cur_ack_rel, end_tcp_seq);
//                 // print_func("[Range] cur_ack_rel %u >= it->end %u, delete, erase count %d\n", cur_ack_rel, end_tcp_seq, erase_count);
//                 // print_func("before erase it: [%u, %u]\n", it->start, it->end);
//                 range_job_vector.erase(it++);
//                 if(!range_job_vector.size())
//                     break;
//                 // print_func("after erase it: [%u, %u]\n", it->start, it->end);
//                 continue;
//             }
//             if(!it->sent_epoch_time){
//                 if(is_ssl){
// #ifdef USE_OPENSSL
//                     send_http_range_request(range_ssl, &(*it));
// #endif
//                 }
//                 else
//                     send_http_range_request((void*)range_sockfd, &(*it));

//                 it->sent_epoch_time = get_current_epoch_time_second();
//                 // print_func("[Range]: sent range[%u, %u]\n", it->start+obj->response_header_len+1, it->end+obj->response_header_len+1);
//             }
//             else if (get_current_epoch_time_nanosecond() - it->sent_epoch_time >= 10){//timeout, send it again
//                 double delay = get_current_epoch_time_nanosecond() - it->sent_epoch_time;
//                 range_timeout_cnt++;
//                 range_timeout_penalty += delay;
//                 uint start_tcp_seq = get_tcp_seq(it->start);
//                 log_info("[Range] [%u, %u] timeout %.2f, close and restart\n", start_tcp_seq, end_tcp_seq, delay);
//                 print_func("[Range] [%u, %u] timeout %.2f, close and restart\n", start_tcp_seq, end_tcp_seq, delay);
//                 // close(range_sockfd);
//                 cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
//                 // range_sockfd_old = range_sockfd;
//                 // range_sockfd = -1;
//                 break;
//             }
//             it++;

//         }
//         // pthread_mutex_unlock(p_mutex_range_job_vector);

//         // Receiving packet
//         // print_func("Receiving packet\n");
//         if(recv_offset == 0)
//             memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset+1);
//         if(is_ssl){
// #ifdef USE_OPENSSL
//             rv = SSL_read(range_ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
// #endif
//         }
//         else{
//             rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);
//         }

//         if (rv > 0) {
//             log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
//             print_func("[Range] recved %d bytes, hand over to process_range_rv\n", rv);
//             process_range_rv(response, rv, this, subconn, header, consumed, unread, parsed, recv_offset, unsent);
//         }
//         else if(rv == 0){
//             if(!is_ssl){
//                 if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
//                     continue;
//             }

//             if(rv == 0){
//                 log_debug("[Range] recv ret %d, sockfd %d closed ", rv, range_sockfd);
//                 print_func("[Range] recv ret %d, sockfd %d closed\n", rv, range_sockfd);
//             }
//             else{
//                 log_debug("[Range] error: ret %d errno %d", rv, errno);
//                 print_func("[Range] error: ret %d errno %d\n", rv, errno);
//             }
//             cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
//             print_func("closed range_sockfd %d\n", range_sockfd);
// #ifdef USE_OPENSSL
//             if(is_ssl)
//                 range_ssl_old = range_ssl;
// #endif
//         }
//         usleep(100);
//     }
//     free(header);
//     header = NULL;

//     print_func("[Range]: range_watch thread exits...\n");
//     // pthread_exit(NULL);
//     return;
}




void Optimack::try_for_gaps_and_request(){
//     uint last_recv_inorder;
   
//     last_recv_inorder = recved_seq.getFirstEnd();
//     if(check_packet_lost_on_all_conns(last_recv_inorder)){
//         uint first_out_of_order = recved_seq.getElem_withLock(1,true);// ;getIntervalList().at(1).start
//         if(is_ssl){
// #ifdef USE_OPENSSL
//             uint second_end = recved_seq.getElem_withLock(1,false);
//             if(second_end == first_out_of_order)
//                 return;
// #endif
//         }
//         if(first_out_of_order){
//             insert_lost_range(recved_seq.getFirstEnd(), first_out_of_order-1);
//         }
//     }
}


bool Optimack::check_packet_lost_on_all_conns(uint last_recv_inorder){
    
    if (recved_seq.size() < 1 || recved_seq.getFirstStart() == 1)
        return false;

    if(is_ssl){
#ifdef USE_OPENSSL
        if(!this->tls_record_seq_map)
            return false;
        TLS_Record_Seq_Info* seq_info = this->tls_record_seq_map->get_record_seq_info(last_recv_inorder+1);
        if(seq_info){
            last_recv_inorder = seq_info->upper_seq - 1;
            // print_func("[Range] check_packet_lost_on_all_conns: get_record_seq_info %d\n", last_recv_inorder+1);
        }
#endif
    }

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        // log_info("first: recved_seq.lastend %u, last_recv_inorder %u", it->second->recved_seq.getLastEnd(), last_recv_inorder);
        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL                
//         if(is_ssl)
//             next_seq_rem = it->second->next_seq_rem_tls;
// #endif        
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && next_seq_rem <= last_recv_inorder){
            // log_info("<=, return false\n");
            return false;
        }
        // else
        //     print_func(">, continue\n");
    }
    usleep(1000);
    char tmp[1000] = {0};
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        // sprintf(tmp, "%s %d:%u", tmp, it->second->id, it->second->next_seq_rem);
        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL                
//         if(is_ssl)
//             next_seq_rem = it->second->next_seq_rem_tls;
// #endif
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && next_seq_rem <= last_recv_inorder){
            log_info("second: %s, <=, return false", tmp);
            return false;
        }
    }
    // sprintf(tmp, "%s recved_seq.FirstEnd:%u", tmp, recved_seq.getFirstEnd());
    // log_info("lost on all: %s", tmp);
    return true;
}
