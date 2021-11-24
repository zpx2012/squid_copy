#include "hping2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <ctime>
#include <sys/time.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <iterator>
using namespace std;

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include <netinet/tcp.h>
#include "socket.h"
#include "util.h"
#include "checksum.h"
// #include "Debug.h"
#include "logging.h"

// for http parsing
#include <cstring>
#include <algorithm>
#include "squid.h"
#include "sbuf/SBuf.h"
#include "http/one/RequestParser.h"
#include "http/one/ResponseParser.h"
// #include "../../include/squid.h"
// #include "../sbuf/SBuf.h"
// #include "../http/one/RequestParser.h"
// #include "../http/one/ResponseParser.h"

#include "Optimack.h"

#ifdef OPENSSL
#include <openssl/ssl.h>
#include "get_server_key.h"
void test_write_key(SSL *s){
    if(!s)
        return;

    unsigned char session_key[20],iv_salt[4];
    get_server_session_key_and_iv_salt(s, session_key, iv_salt);
    // printf("get write iv and salt: %s\n", buf);

    // printf("get server key: %s\n", buf);
}
#endif

/** Our code **/
#ifndef CONN_NUM
#define CONN_NUM 6
#endif

#ifndef ACKPACING
#define ACKPACING 1000
#endif

#define MAX_STALL_TIME 240

#define LOGSIZE 10240
#define IPTABLESLEN 128

// nfq
#define NF_QUEUE_NUM 6
#define NFQLENGTH 204800
#define BUFLENGTH 4096
// range
#define MAX_REQUEST_LEN 1024
#define MAX_RANGE_REQ_LEN 1536
#define MAX_RANGE_SIZE 14600
#define PACKET_SIZE 1460

#ifndef RANGE_MODE
#define RANGE_MODE 1
#endif

#ifndef BACKUP_MODE
#define BACKUP_MODE 0
#endif

#ifndef MSS
#define MSS 1460
#endif

#ifndef SPEEDUP_CONFIG
#define SPEEDUP_CONFIG 0
#endif

#ifndef SLOWDOWN_CONFIG
#define SLOWDOWN_CONFIG 0
#endif

#ifndef DEBUG_PRINT_LEVEL
#define DEBUG_PRINT_LEVEL 0
#endif


// Utility
double get_current_epoch_time_second(){
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

double get_current_epoch_time_nanosecond(){
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()/1000000000.0;
}

double elapsed(std::chrono::time_point<std::chrono::system_clock> start){
    auto now = std::chrono::system_clock::now();
    if (now > start)
        return std::chrono::duration<double>(now - start).count();
    else 
        return 0;
}

bool is_timeout_and_update(std::chrono::time_point<std::chrono::system_clock> &start, double timeout){
    if (elapsed(start) < timeout)
        return false;
    start = std::chrono::system_clock::now();
    return true;        
}

string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

template <typename Out>
void split(const std::string &s, char delim, Out result) {
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        if(!item.empty())
            *result++ = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

char* get_cur_time_str(char* time_str, char* format_str){
    struct tm timeinfo;
    // timeval cur_timeval;
    // gettimeofday (&cur_timeval, NULL);
    // timeinfo = localtime(&cur_timeval.tv_sec);
    // strftime(time_str, 20, format_str, timeinfo);

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    localtime_r(&now, &timeinfo);
    std::strftime(time_str, 64, format_str, &timeinfo);
    
    return time_str;
}

char* print_chrono_time(std::chrono::time_point<std::chrono::system_clock> time_point, char* time_str){
    struct tm timeinfo;
    std::time_t time_t = std::chrono::system_clock::to_time_t(time_point);
    localtime_r(&time_t, &timeinfo);
    std::strftime(time_str, 64, "%Y-%m-%d %H:%M:%S", &timeinfo);
    return time_str;
}

char* time_in_YYYY_MM_DD(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%d");
}

char* time_in_HH_MM_SS(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%d %H:%M:%S");
}

char* time_in_HH_MM_SS_nospace(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%dT%H:%M:%S");
}

char* time_in_HH_MM_SS_US(char* time_str){
    struct tm * timeinfo;
    timeval cur_timeval;
    gettimeofday(&cur_timeval, NULL);
    timeinfo = localtime(&cur_timeval.tv_sec);
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    sprintf(time_str, "%s.%06ld", time_str, cur_timeval.tv_usec);
    return time_str;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

void*
nfq_loop(void *arg)
{
    int rv;
    char buf[65536];
    //void * placeholder = 0;

    Optimack* obj = (Optimack*)arg;
    log_info("nfq_loop thread starts");
    while (!(obj->nfq_stop)) {
        rv = recv(obj->g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            //debugs(0, DBG_CRITICAL,"%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(obj->g_nfq_h, buf, rv);
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                // debugs(0, DBG_CRITICAL,"recv() ret " << rv << " errno " << errno);
                // printf("recv() ret %d errno %d\n", rv, errno);
            }
            usleep(100); //10000
        }
    }
    log_info("nfq_loop thread ends");
    pthread_exit(NULL);
    //return placeholder;
}

void* 
pool_handler(void* arg)
{
    //char log[LOGSIZE];
    struct thread_data* thr_data = (struct thread_data*)arg;
    Optimack* obj = (Optimack*)(thr_data->obj);
    u_int32_t id = thr_data->pkt_id;
    int ret = -1;

    if(obj->cb_stop)
        return NULL;
    //debugs(0, DBG_CRITICAL, "pool_handler: "<<id);
    if(!thr_data->buf)
        return NULL;

    short protocol = ip_hdr(thr_data->buf)->protocol;
    if (protocol == 6)
        ret = obj->process_tcp_packet(thr_data);
    else{ 
        printf("Invalid protocol: 0x%04x, len %d", protocol, thr_data->len);
        //debugs(0, DBG_CRITICAL, log);
        struct myiphdr *iphdr = ip_hdr(thr_data->buf);
        // struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);

        //unsigned char *payload = tcp_payload(thr_data->buf);
        // unsigned int payload_len = thr_data->len - iphdr->ihl*4 - tcphdr->th_off*4;
        char sip[16], dip[16];
        ip2str(iphdr->saddr, sip);
        ip2str(iphdr->daddr, dip);

        //memset(log, 0, LOGSIZE);
        //sprintf(log, "%s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", sip, ntohs(tcphdr->th_sport), dip, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
        //debugs(0, DBG_CRITICAL, log);
        // char* hex_str = hex_dump_str(thr_data->buf, thr_data->len);
        //debugs(0, DBG_CRITICAL, hex_str);
        // free(hex_str);
        // hex_str = NULL;
    }

    if (ret == 0){
        nfq_set_verdict(obj->g_nfq_qh, id, NF_ACCEPT, thr_data->len, thr_data->buf);
        // log_info("Verdict: Accept");
        //debugs(0, DBG_CRITICAL, "Verdict: Accept");
    }
    else{
        nfq_set_verdict(obj->g_nfq_qh, id, NF_DROP, 0, NULL);
        // log_info("Verdict: Drop");
        //debugs(0, DBG_CRITICAL, "Verdict: Drop");
    }

    free(thr_data->buf);
    thr_data->buf = NULL;
    free(thr_data);
    thr_data = NULL;
    // TODO: ret NULL?
    return NULL;
}

void adjust_optimack_speed(struct subconn_info* conn, int id, int mode, int offset){
    //mode: 1 - speedup, -1 - slowdown
    if(conn->ack_pacing > 500 && conn->ack_pacing - offset > 10){
        conn->ack_pacing -= mode*offset;
        if(mode == 1)
            printf("S%d: adjust - speed up by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
        else if(mode == -1)
            printf("S%d: adjust - slow down by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
        else
            printf("S%d: unknown mode!\n", id);
    }
    else {
        conn->payload_len += mode*offset;
        if(mode == 1)
            printf("S%d: adjust - speed up by ack_pace by %d to %d!\n", id, offset, conn->ack_pacing);
        else if(mode == -1)
            printf("S%d: adjust - slow down by ack_pace by %d to %d!\n", id, offset, conn->ack_pacing);
        else
            printf("S%d: unknown mode!\n", id);    }
}

void adjust_optimack_speed_by_ack_interval(struct subconn_info* conn, int id, int offset)
{
    if(conn->ack_pacing - offset > 10){
        conn->ack_pacing -= offset;
        printf("S%d: speed up by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
    }
}

void adjust_optimack_speed_by_ack_step(struct subconn_info* conn, int id, int offset)
{
    conn->payload_len += offset;
    printf("S%d: speed up by ack_step by %d to %d!\n", id, offset, conn->payload_len);
}


bool Optimack::is_nfq_full(FILE* out_file){
    std::string rst_str = exec("cat /proc/net/netfilter/nfnetlink_queue");
    fprintf(out_file, "cat /proc/net/netfilter/nfnetlink_queue: %s", rst_str.c_str());
    // cout << "cat /proc/net/netfilter/nfnetlink_queue:\n " << rst_str << endl;
    std::vector<std::string> fields = split(rst_str, ' ');
    if(fields.size() > 7){
        if(fields.at(5) != "0" || fields.at(6) != "0"){
            fprintf(out_file, "\n\n###################\nNetfilter Queue too full!\n###################\n");
            return true;
        }
    }
    else
        fprintf(out_file, "Error! nfnetlink_queue result is shorter than 7 fields!");
    return false;
}

void Optimack::print_ss(FILE* out_file){
    char cmd[100];
    snprintf(cmd, 100, "ss -o state established '( sport = %d )' -tnm", squid_port);
    std::string rst_str = exec(cmd);
    fprintf(out_file, "%s", rst_str.c_str());
    // cout << "cat /proc/net/netfilter/nfnetlink_queue:\n " << rst_str << endl;
    return;
}

bool Optimack::does_packet_lost_on_all_conns(){
    // get_server_write_key(NULL, NULL);
    return false;
}
//     // Packet lost on all connections
//     bool is_all_lost = true;
    
//     // log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - trying lock"); 
//     // pthread_mutex_lock(&mutex_seq_gaps);
//     for(size_t i = 0; i < subconn_infos.size(); i++){
//         pthread_mutex_lock(&subconn_infos[i].mutex_opa);
//         // printf("next_seq_rem %u, cur_ack_rel %u, payload_len %u\n", subconn_infos[i].next_seq_rem, cur_ack_rel, subconn_infos.begin()->payload_len);
//         if (subconn_infos[i].next_seq_rem <= cur_ack_rel){//Why seq_gaps? because squid might drop some packets forwarded to it
//             if(!subconn_infos[i].recved_seq.getIntervalList().empty() && subconn_infos[i].next_seq_rem < subconn_infos[i].recved_seq.getFirstEnd_withLock()){
//                 printf("Error: subconn_infos[i].next_seq_rem(%u) < subconn_infos[i].seq_gaps.at(0).start(%u)\n", subconn_infos[i].next_seq_rem, subconn_infos[i].seq_gaps.at(0).start);
//             }
            
//             if (subconn_infos[i].next_seq_rem != subconn_infos[i].last_next_seq_rem){
//                 log_debug("S%u: next_seq_rem %u, subconn_infos[i].seq_gaps[0].start %u", i, subconn_infos[i].next_seq_rem, subconn_infos[i].seq_gaps[0].start);  
//                 subconn_infos[i].last_next_seq_rem = subconn_infos[i].next_seq_rem;
//             }
//             is_all_lost = false;
//             pthread_mutex_unlock(&subconn_infos[i].mutex_opa);
//             break;
//         }
//         else if(!subconn_infos[i].seq_gaps.empty() && subconn_infos[i].next_seq_rem == subconn_infos[i].seq_gaps.at(0).start){
//             log_error("S%u: Didn't remove [%u, %u], next_seq_rem %u", i, subconn_infos[i].seq_gaps[0].start, subconn_infos[i].seq_gaps[0].end, subconn_infos[i].next_seq_rem);
//         }
//         pthread_mutex_unlock(&subconn_infos[i].mutex_opa);
//     }

//     if (is_all_lost){
//         // is_nfq_full();

//         printf("\n\n###################\nPacket lost on all connections. \n###################\n\nlast ack:%d\n", cur_ack_rel);
//         for(size_t i = 1; i < subconn_infos.size(); i++){
//             printf("S%d: %d\n", i, subconn_infos[i].next_seq_rem);
//         }
//         // if(seq_gaps[0].start < cur_ack_rel){
//         //     printf("ACK packet, gap removal wrong!!!\n");
//         // }
//         // printIntervals(seq_gaps);
//         log_seq_gaps();
//         // for (int i = 0; i < seq_gaps.size(); i++)
//         //     log_debugv("[%u, %u], ", seq_gaps[i].start, seq_gaps[i].end);

//         // logIntervals(seq_gaps, )
//         sleep(5);
//         exit(-1);
//     }
//     // pthread_mutex_unlock(&mutex_seq_gaps);
//     // log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - unlock"); 
    
//     return is_all_lost;    
// }

char empty_payload[] = "";

int Optimack::get_ajusted_rwnd(int cur_ack){
    int cur_rwnd = rwnd + cur_ack_rel - cur_ack;
    // cur_rwnd = cur_rwnd / squid_MSS * squid_MSS;
    int diff = (int)(cur_rwnd - squid_MSS);
    // uint cur_win_scaled = diff <= 0? 0 : cur_rwnd / win_scale;
    if (diff <= 0)
        return 0;
    return cur_rwnd;
}

int Optimack::get_ajusted_rwnd_backup(int cur_ack){
    int cur_rwnd = 65535*4 + cur_ack_rel - cur_ack;
    int diff = (int)(cur_rwnd - squid_MSS);
    if (diff <= 0)
        return 0;
    return cur_rwnd;
}

void Optimack::send_optimistic_ack(struct subconn_info* conn, int cur_ack, int adjusted_rwnd){
    if(adjusted_rwnd < conn->win_scale)
        return;
    uint cur_win_scaled = adjusted_rwnd / conn->win_scale;
    send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);
    log_info("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u", conn->local_port, cur_ack, conn->next_seq_loc, cur_win_scaled);
    return;
}

void Optimack::send_optimistic_ack_with_SACK(struct subconn_info* conn, int cur_ack, int adjusted_rwnd, IntervalList* recved_seq){
    if(adjusted_rwnd < conn->win_scale)
        return;
    uint cur_win_scaled = adjusted_rwnd / conn->win_scale;
    unsigned char sack_str[33] = {0};
    // int len = generate_sack_blocks(sack_str, 32, recved_seq);//TODO:bug
    send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);
    // send_ACK_with_SACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, sack_str, len, "", conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);
    log_info("[send_optimistic_ack_with_SACK] S%u: sent ack %u, seq %u, tcp_win %u", conn->local_port, cur_ack, conn->next_seq_loc, cur_win_scaled);
    return;
}

int Optimack::send_ACK_adjusted_rwnd(struct subconn_info* conn, int cur_ack){ //std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    // cur_win_scale = obj->rwnd / obj->win_scale;
    int cur_rwnd = rwnd/2 + cur_ack_rel - cur_ack;
    conn->rwnd = cur_rwnd;
    int diff = (int)(cur_rwnd - (int)conn->payload_len*2);
    uint cur_win_scaled = diff <= 0? 0 : cur_rwnd / conn->win_scale;
    send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, cur_ack + conn->ini_seq_rem, conn->opa_seq_start, cur_win_scaled);
    log_info("[send_ACK_adjusted_rwnd] S%u: sent ack %u, seq %u, win %d, win_end %u, tcp_win %u", conn->local_port, cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_rwnd, rwnd/2 + cur_ack_rel, cur_win_scaled);
    if (diff <= 0)
        return -1;
    return 0;

    // if(conn->is_backup)
        // printf("obj->rwnd %u, subconn_cur_ack %u, cur_ack_rel %u, conn->rwnd %u\n", obj->rwnd, cur_ack, obj->cur_ack_rel, conn->rwnd);

        // if (conn->is_backup)        
            // printf("O-bu: ack %u, seq %u, win_scaled %d\n", cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_win_scaled);
}


int Optimack::send_optimistic_ack_with_timer(struct subconn_info* conn, int cur_ack, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    last_send_ack = std::chrono::system_clock::now();
    if(send_ACK_adjusted_rwnd(conn, cur_ack) == 0){
        last_zero_window = std::chrono::system_clock::now();
        return 0;
    }
    else {
        if (!RANGE_MODE && is_timeout_and_update(last_zero_window, 2)){
            log_info("S%u: cur_win_scale == 0", conn->local_port);
            // obj->does_packet_lost_on_all_conns();
            // printIntervals(obj->seq_gaps);
        }
        return -1;
    }
}

void Optimack::update_optimistic_ack_timer(bool is_zero_window, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    last_send_ack = std::chrono::system_clock::now();
    if(is_zero_window){
        last_zero_window = std::chrono::system_clock::now();
        char time_str[20];
        // log_info("[optack]: set zero window timer to %s\n", print_chrono_time(last_zero_window, time_str));
        return;
    }
    // else {
    //     if (is_timeout_and_update(last_zero_window, 2)){
    //         // log_info("cur_win_scale == 0");
    //     }
    //     return;
    // }    
}

void* selective_optimistic_ack(void* arg){
    struct int_thread* ack_thr = (struct int_thread*)arg;
    int id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = (obj->subconn_infos[id]);
    unsigned int opa_seq_start = conn->opa_seq_start;
    unsigned int local_port = conn->local_port, payload_len = conn->payload_len;
    free(ack_thr);
    ack_thr = NULL;

    double send_ack_pace = 1500 / 1000000.0;

    std::chrono::time_point<std::chrono::system_clock> last_send_ack, last_data_update, last_log_adjust_rwnd, last_zero_window, last_dup_ack_time;
    last_send_ack = last_data_update = last_log_adjust_rwnd = last_zero_window = last_dup_ack_time = std::chrono::system_clock::now();
    // bool is_zero_window = true;

    std::set<uint> acks_to_be_sent;
    IntervalList sent_ranges;
    uint last_cur_ack_rel = 1;
    uint opa_ack_cur = 1;
    // uint opa_ack_start = 1, opa_ack_end = obj->cur_ack_rel - payload_len;
    uint last_recved_seq = 1, last_dup_ack = 1;
    while(!conn->optim_ack_stop){

        // Add optimack ranges
        if(elapsed(obj->last_ack_time) <= 1){
            if(acks_to_be_sent.empty() || (!acks_to_be_sent.empty() && *acks_to_be_sent.rbegin() < obj->cur_ack_rel)){
                last_recved_seq = conn->recved_seq.getFirstEnd();
                if(last_recved_seq && obj->cur_ack_rel >= last_recved_seq+payload_len){
                    uint insert_start = last_recved_seq;//-2*payload_len
                    if(conn->next_seq_rem < obj->cur_ack_rel)
                        insert_start = conn->next_seq_rem - 2*payload_len;
                    uint sent_range_end = sent_ranges.getLastEnd();
                    log_debug("[Backup]: insert_start %u, sent_range_end %u", insert_start, sent_range_end);
                    if (sent_range_end && last_recved_seq < sent_range_end)
                        insert_start = sent_range_end;
                    for(uint i = insert_start; i < obj->cur_ack_rel; i += payload_len){
                        if(i > sent_range_end)
                            acks_to_be_sent.insert(i);
                    }
                    conn->recved_seq.insertNewInterval_withLock(1, obj->cur_ack_rel);
                    log_debug("[Backup]: add optim range [%u,%u], conn->recved_seq after %s\n", insert_start, obj->cur_ack_rel, conn->recved_seq.Intervals2str().c_str());
                }
            }
        }

        //start optimistic ack to recved_seq[0].end, after recved packets to recved_seq[0].end, add [conn->seq_gaps[0].end, obj->recved_seq[0].end]
        // if(elapsed(last_send_ack) >= send_ack_pace){
        //     uint last_inorder_seq = conn->recved_seq.getFirstEnd();

        //     if(opa_ack_cur < last_inorder_seq) //Don't start from 1
        //         opa_ack_cur = last_inorder_seq;

        //     if(last_recved_seq && obj->cur_ack_rel >= last_recved_seq+5*payload_len){
        //         if(opa_ack_cur < last_recved_seq)
        //             opa_ack_cur = last_recved_seq;
        //     }

        //     if(opa_ack_cur < obj->cur_ack_rel){
        //         int adjusted_rwnd = obj->get_ajusted_rwnd(opa_ack_cur);
        //         if(adjusted_rwnd > conn->win_scale){
        //             obj->send_optimistic_ack(conn, opa_ack_cur, adjusted_rwnd);
        //             opa_ack_cur += obj->squid_MSS;
        //         }
        //         obj->update_optimistic_ack_timer(adjusted_rwnd <= 0, last_send_ack, last_zero_window);
        //     }
        // }

        if (!acks_to_be_sent.empty() && elapsed(last_send_ack) >= send_ack_pace){
            uint cur_ack = *acks_to_be_sent.begin();
            int adjusted_rwnd = obj->get_ajusted_rwnd_backup(cur_ack);
            obj->update_optimistic_ack_timer(adjusted_rwnd <= 0, last_send_ack, last_zero_window);
            if(adjusted_rwnd > conn->win_scale){
                obj->send_optimistic_ack(conn, cur_ack, adjusted_rwnd);
                log_info("[Backup]: sent optack %u\n", cur_ack);
                // printf("[Backup]: sent optack %u\n", cur_ack);
                acks_to_be_sent.erase(acks_to_be_sent.begin());
                sent_ranges.insertNewInterval(cur_ack, cur_ack+payload_len);
                if(cur_ack > obj->backup_max_opt_ack)
                    obj->backup_max_opt_ack = cur_ack;
            }
        }

        // Ignore gaps in optimack_ranges and before
        char tmp[100];
        if(!sent_ranges.getIntervalList().empty()) {
            uint last_recved_seq_end = conn->next_seq_rem;
        //  uint last_recved_seq_end = conn->recved_seq.getLastEnd();
            if (last_recved_seq_end){// && last_cur_ack_rel != last_recved_seq_end){ //&& inIntervals(sent_ranges, cur_ack_rel)){
        //         last_cur_ack_rel = last_recved_seq_end;

                uint insert_interval_end = last_recved_seq_end;
                uint sent_range_last_end = sent_ranges.getLastEnd();
                sprintf(tmp, "Padding gaps: last_recved_seq_end-%u, sent_ranges.getLastEnd()-%u", last_recved_seq_end, sent_range_last_end);
                if (last_recved_seq_end > sent_range_last_end){
                    insert_interval_end = sent_range_last_end;
                    sent_ranges.getIntervalList().clear();
                    for(; !acks_to_be_sent.empty() && *acks_to_be_sent.begin() < last_recved_seq_end; acks_to_be_sent.erase(acks_to_be_sent.begin()));
                    sprintf(tmp, "%s < , ", tmp);
                }
                else if (last_recved_seq_end > sent_ranges.getIntervalList().at(0).start){
                    sent_ranges.removeInterval(1, last_recved_seq_end);
                    sprintf(tmp, "%s > , ", tmp);
                //     insert_interval_end = last_recved_seq_end; 
                }
                log_debug(tmp);
                // else // last_recved_seq_end < sent_ranges.begin()->start, not in optimack range, but doesn't matter anymore
                //     insert_interval_end = last_recved_seq_end;
                // conn->recved_seq.insertNewInterval_withLock(1, insert_interval_end);
        //         if (is_timeout_and_update(last_log_adjust_rwnd,2)){
        //             if(!acks_to_be_sent.empty()){
        //                 printf("%s sent ranges [%u, %u], acks_to_sent[%u, %u]\n", tmp, sent_ranges.getFirstEnd(), sent_ranges.getLastEnd(), *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
        //                 log_info("%s sent ranges [%u, %u], acks_to_sent[%u, %u]\n", tmp, sent_ranges.getFirstEnd(), sent_ranges.getLastEnd(), *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
        //             }
        //             // conn->recved_seq.printIntervals_withLock();
        //         }
            } 
        }

        if(elapsed(conn->last_data_received) > 2){
            uint inorder_seq_end = conn->recved_seq.getFirstEnd();
            if(inorder_seq_end <= conn->next_seq_rem && !(inorder_seq_end == last_dup_ack && elapsed(last_dup_ack_time) < 5)){//optack, don't need retranx
                int backup_rwnd_tmp = obj->backup_dup_ack_rwnd;
                if(inorder_seq_end != obj->backup_dup_ack || backup_rwnd_tmp <= conn->win_scale)
                    backup_rwnd_tmp = obj->backup_dup_ack + obj->backup_dup_ack_rwnd - inorder_seq_end;
                if(backup_rwnd_tmp <= conn->win_scale)
                    backup_rwnd_tmp = conn->win_scale*2;
                if(inorder_seq_end < obj->backup_max_opt_ack){
                    printf("[Backup]: Error! Duplicate ACK(%u) < backup_max_opt_ack(%u)\n\n", inorder_seq_end, obj->backup_max_opt_ack);
                    log_error("[Backup]: Error! Duplicate ACK(%u) < backup_max_opt_ack(%u)\n", inorder_seq_end, obj->backup_max_opt_ack);
                }
                else if(backup_rwnd_tmp > conn->win_scale){ //&& inorder_seq_end != last_dup_ack
                    if(inorder_seq_end > obj->backup_max_opt_ack)
                        obj->backup_max_opt_ack = inorder_seq_end;
                    for (int j = 0; j < 10; j++){
                        obj->send_optimistic_ack(conn, inorder_seq_end, backup_rwnd_tmp);
                        usleep(1000);
                        // obj->send_optimistic_ack_with_SACK(conn, inorder_seq_end, obj->rwnd, &conn->recved_seq);
                        // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + inorder_seq_end, ack, cur_win_scale);
                    }
                    printf("[Backup]: O-bu: retrx - Sent ack %u\n\n", inorder_seq_end);
                    log_info("[Backup]: O-bu: retrx - Sent ack %u\n", inorder_seq_end);
                    last_dup_ack = inorder_seq_end;
                    last_dup_ack_time = std::chrono::system_clock::now();
                }
                else if (backup_rwnd_tmp <= conn->win_scale){
                    printf("[Backup]: O-bu: retrx - Didn't send ack %u, window < 0\n\n", inorder_seq_end);
                    log_info("[Backup]: O-bu: retrx - Didn't send ack %u, window < 0\n", inorder_seq_end);
                }
            }
        }

        // Overrun detection
        if(is_timeout_and_update(conn->last_data_received, 4)){
            uint ack_restart_start, ack_restart_end;
            if(!sent_ranges.getIntervalList().empty()){
                uint min_ack_sent = sent_ranges.getIntervalList().at(0).start;
                if(min_ack_sent == 0)
                    min_ack_sent = 1;
                ack_restart_start = std::min(min_ack_sent, last_recved_seq); 
                ack_restart_end = *acks_to_be_sent.begin();
                sent_ranges.removeInterval(ack_restart_start, ack_restart_end);
            // else {//Can't use it because it can add normal range to optimistic acks
                // ack_restart_start = conn->next_seq_rem - 2*payload_len;
                // ack_restart_end = obj->cur_ack_rel;
            // }
                sprintf(tmp,"O-bu: overrun, restart %u to %u\n", ack_restart_start, ack_restart_end);
                if(!acks_to_be_sent.empty())
                    sprintf(tmp, "%sBefore: [%u, %u]\n", tmp, *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
                // std::copy(,acks_to_be_sent.end(), std::ostream_iterator<uint>(std::cout, " "));
                for(uint i = ack_restart_start; i < ack_restart_end; i += payload_len)
                    acks_to_be_sent.insert(i);
                if(!acks_to_be_sent.empty())
                    sprintf(tmp, "%sAfter: [%u, %u]\n", tmp, *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
                printf(tmp);
                log_debug(tmp);
            // delete overruned range from sent_ranges
            }
        }

        // usleep(10);
    }
    conn->optim_ack_stop = 0;
    log_info("S%d-bu: optimistic ack ends", id);
    pthread_exit(NULL);
}

void* 
full_optimistic_ack(void* arg)
{
    struct int_thread* ack_thr = (struct int_thread*)arg;
    uint id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = (obj->subconn_infos[id]);
    free(ack_thr);
    ack_thr = NULL;

    log_info("S%d: optimistic ack started", id);

    auto last_send_ack = std::chrono::system_clock::now(), last_zero_window = std::chrono::system_clock::now(), last_restart = std::chrono::system_clock::now();
    unsigned int opa_ack_start = 1, zero_window_start = -1;
    // unsigned int ack_step = conn->payload_len;
    double send_ack_pace = conn->ack_pacing / 1000000.0;
    int send_ret = 0;
    while (!conn->optim_ack_stop) {
        if (elapsed(last_send_ack) >= send_ack_pace){
            send_ret = obj->send_optimistic_ack_with_timer(conn, opa_ack_start, last_send_ack, last_zero_window);
            if(send_ret < 0)
                zero_window_start = opa_ack_start;
            else 
                opa_ack_start += conn->payload_len;

            if (SPEEDUP_CONFIG){
                if(obj->cur_ack_rel > opa_ack_start && conn->next_seq_rem > opa_ack_start){
                    opa_ack_start = conn->next_seq_rem;
                }
                if(conn->next_seq_rem > opa_ack_start){
                    opa_ack_start = conn->next_seq_rem;
                }

                // if(conn->next_seq_rem-opa_ack_start > 1460*100 && conn->next_seq_rem > opa_ack_start && elapsed(obj->last_speedup_time) > 10){ //&& obj->subconn_infos.begin()->off_pkt_num < 1
                //     log_debugv("optimistic_ack: mutex_subconn_infos - tring lock");
                //     pthread_mutex_lock(&obj->mutex_subconn_infos);
                //     if(conn->next_seq_rem-opa_ack_start > 1460*100 && conn->next_seq_rem > opa_ack_start && elapsed(obj->last_speedup_time) > 10){ //&& obj->subconn_infos.begin()->off_pkt_num < 1 
                //         // for (int i = 0; i < obj->subconn_infos.size(); i++)
                //         // for (auto const& [port, subconn] : obj->subconn_infos) 
                //         for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++)
                //             adjust_optimack_speed(&it->second, it->second->id, 1, 10);//low frequence
                //         obj->last_speedup_ack_rel = opa_ack_start - conn->ini_seq_rem;
                //         obj->last_speedup_time = std::chrono::system_clock::now();
                //     }
                //     pthread_mutex_unlock(&obj->mutex_subconn_infos);
                //     log_debugv("optimistic_ack: mutex_subconn_infos - unlock");
                // }
            }
        }

        //Overrun detection
        if (elapsed(conn->last_data_received) >= 2){ //zero_window_start - conn->next_seq_rem > 3*conn->payload_len && 
            // if((send_ret >= 0 || (send_ret < 0 && zero_window_start > conn->next_seq_rem)){
            if(!SPEEDUP_CONFIG && opa_ack_start < conn->next_seq_rem)
                continue;
            if(elapsed(last_restart) >= 2){
                if(send_ret < 0 && zero_window_start <= conn->next_seq_rem) //Is in zero window period, received upon the window end, not overrun
                    continue;
                printf("S%u: overrun, current ack %u, ", id, opa_ack_start);
                opa_ack_start = conn->next_seq_rem - 5*conn->payload_len;
                last_restart = std::chrono::system_clock::now();
                printf("restart at %u, zero_window_start %u, next_seq_rem %u\n", opa_ack_start, zero_window_start, conn->next_seq_rem);
            }

            // if(elapsed(conn->last_data_received) >= 120){
            //     printf("Overrun bug occurs: S%u, %u\n", id, conn->next_seq_rem);
            //     exit(-1);
            // }
        }

        usleep(10);
    }

    conn->optim_ack_stop = 0;
    log_info("S%d: optimistic ack ends", id);
    pthread_exit(NULL);
}

void* 
full_optimistic_ack_altogether(void* arg)
{
    struct int_thread* ack_thr = (struct int_thread*)arg;
    // uint id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    uint mss = obj->squid_MSS;
    // struct subconn_info* conn = (obj->subconn_infos[id]);
    free(ack_thr);
    ack_thr = NULL;

    log_info("Optimistic ack started");

    auto last_send_ack = std::chrono::system_clock::now(), last_zero_window = std::chrono::system_clock::now(), 
         last_restart  = std::chrono::system_clock::now(), last_overrun_check = std::chrono::system_clock::now();
    unsigned int opa_ack_start = 1, last_stall_seq = 1, last_stall_port = 1, last_restart_seq = 0, same_restart_cnt = 0, opa_ack_dup_countdown = 0;
    long zero_window_start = 0;
    // unsigned int ack_step = conn->payload_len;
    double send_ack_pace = ACKPACING / 1000000.0;
    int adjusted_rwnd = 0;
    char log[200] = {0};
    bool is_in_overrun = false;

    while (!obj->optim_ack_stop) {
        if (elapsed(last_send_ack) >= send_ack_pace){
            //calculate adjusted window size
            adjusted_rwnd = obj->get_ajusted_rwnd(opa_ack_start);
            obj->adjusted_rwnd = adjusted_rwnd;
            for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++){
                if(!it->second->is_backup && !it->second->fin_or_rst_recved){
                    if (adjusted_rwnd <= it->second->win_scale){
                        if(elapsed(last_zero_window) < 2){
                            adjusted_rwnd = 0;
                            // obj->send_optimistic_ack(it->second, it->second->next_seq_rem, obj->get_ajusted_rwnd(it->second->next_seq_rem));
                            continue;
                            // break;
                        }
                        else{
                            adjusted_rwnd = mss;
                        }
                    }
                    
                    if (opa_ack_start >= obj->max_opt_ack || opa_ack_start == obj->ack_end || (opa_ack_start < obj->max_opt_ack && it->second->next_seq_rem <= opa_ack_start+10*obj->squid_MSS && same_restart_cnt < 3)){ //-> this will cause normal optimistic acks are not sent and server missing lots of acks
                        obj->send_optimistic_ack(it->second, opa_ack_start, adjusted_rwnd);
                        // log_info("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u", it->second->local_port, opa_ack_start, it->second->next_seq_loc, adjusted_rwnd);
                        it->second->opa_ack_start = opa_ack_start;
                    }
                }
            }
            if(adjusted_rwnd > 0){
                if(opa_ack_start > obj->max_opt_ack)
                    obj->max_opt_ack = opa_ack_start;
            }
            obj->update_optimistic_ack_timer(adjusted_rwnd <= 0,last_send_ack, last_zero_window);
            if(adjusted_rwnd <= 0){
                zero_window_start = opa_ack_start;
                // uint min_next_seq_rem = obj->get_min_next_seq_rem();
                // if(abs(zero_window_start-min_next_seq_rem) > 2*obj->squid_MSS){
                //     opa_ack_start = min_next_seq_rem-10*obj->squid_MSS;
                //     // printf("zero window restart at %u, zero_window_start %u\n", opa_ack_start, zero_window_start);
                // }
            }
            else {
                if(obj->cur_ack_rel == obj->ack_end){
                    log_info("[Optimack]: cur_ack_rel == ack_end, mission completed, break from the loop");
                    //send FIN/ACK
                    // send_FIN_ACK(obj->g_local_ip, obj->g_remote_ip, conn->local_port, obj->g_remote_port, "", opa_ack_start+1, conn->next_seq_loc+1);
                    break;
                }
                opa_ack_start += mss;
                if (opa_ack_start > obj->ack_end)
                    opa_ack_start = obj->ack_end;
            }

            // log_info("O: sent ack %u, zero_window_start %u, tcp_win %d, rwnd %d", opa_ack_start, zero_window_start, adjusted_rwnd, obj->rwnd);

            if (SPEEDUP_CONFIG){
                uint min_next_seq_rem = obj->get_min_next_seq_rem();
                if(obj->cur_ack_rel > opa_ack_start && min_next_seq_rem > opa_ack_start){
                    opa_ack_start = obj->cur_ack_rel;
                    printf("speedup: cur ack %u, to %u\n", opa_ack_start, obj->cur_ack_rel);
                }
            //     if(conn->next_seq_rem > opa_ack_start){
            //         opa_ack_start = conn->next_seq_rem;
            //     }
            }
        }

        //Overrun detection
        if (elapsed(last_overrun_check) >= 0.1){
            
            struct subconn_info* slowest_subconn;
            uint min_next_seq_rem = -1;
            // uint min_next_seq_rem = obj->get_min_next_seq_rem();
            uint stall_seq = 0, stall_port = 0;
            bool is_stall = false;
            pthread_mutex_lock(&obj->mutex_subconn_infos);
            // Get slowest subconn
            char tmp_log[1000];
            for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end();it++){
                sprintf(tmp_log, "S%d: is_backup-%d, it->second->next_seq_rem-%u, min-%u", it->second->is_backup, it->second->next_seq_rem, min_next_seq_rem);
                if(!it->second->is_backup && !it->second->fin_or_rst_recved &&  it->second->next_seq_rem < min_next_seq_rem){
                    strcat(tmp_log, "<, update min to next_seq_rem\n");
                    slowest_subconn = it->second;
                    min_next_seq_rem = it->second->next_seq_rem;
                }
            }
            strcat(tmp_log, "\n");
            // if(min_next_seq_rem == -1)
            //     printf(tmp_log);
                
            if(elapsed(slowest_subconn->last_data_received) >= 1.5){
                is_stall = true;
                stall_port = slowest_subconn->local_port;
                stall_seq = slowest_subconn->next_seq_rem;
                // printf("[Optimack]: S%d stalls at %u\n", stall_port, stall_seq);
                sprintf(log, "O: S%d stalls at %u,", stall_port, stall_seq);
                if(slowest_subconn->stall_seq != stall_seq){
                    slowest_subconn->restart_counter = 0;
                    slowest_subconn->stall_seq = stall_seq;
                    log_debug("[Optimack]: S%d stalls at %u, min_next_seq_rem %u", stall_port, stall_seq, min_next_seq_rem);
                }
                // last_stall_seq = stall_seq;
            }
            // for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end();){
            //     if(!it->second->is_backup){
            //         if (elapsed(it->second->last_data_received) >= 2){
            //             is_stall = true;
            //             stall_port = it->second->local_port;
            //             stall_seq = it->second->next_seq_rem;

            //             // if(it->second->recved_seq.getLastEnd() >= min_next_seq_rem && elapsed(it->second->last_data_received) > MAX_STALL_TIME && elapsed(last_zero_window) > 30){
            //             //     char time_str[20];
            //             //     memset(time_str, 0, 20);
            //             //     printf("Full optimistic altogether: S%d Reach max stall time, last_data_received %s, exit...\n", it->second->id, print_chrono_time(it->second->last_data_received, time_str));
            //             //     log_info("Full optimistic altogether: S%d Reach max stall time, last_data_received %s, exit...\n", it->second->id, print_chrono_time(it->second->last_data_received, time_str));
            //             //     obj->subconn_infos.erase(it++);
            //             // }
            //             break;
            //         }
            //     }
            //     it++;
            // }
            pthread_mutex_unlock(&obj->mutex_subconn_infos);

            if (is_stall){ //zero_window_start - conn->next_seq_rem > 3*conn->payload_len && 
                // if((send_ret >= 0 || (send_ret < 0 && zero_window_start > conn->next_seq_rem)){
                if(abs(int(zero_window_start-stall_seq)) <= 3*mss && elapsed(last_zero_window) <= 0.7){ //zero window, exhausted receive window, waiting for new squid ack
                // if (elapsed(last_zero_window) <= 2)//should be 2*rtt || abs(zero_window_start-min_next_seq_rem) < 5*obj->squid_MSS
                    // log_debug("%u-%u <= %u && elapsed(last_zero_window) == %f <= 0.7, continue", zero_window_start, min_next_seq_rem, 3*obj->squid_MSS, elapsed(last_zero_window));
                    // printf("%u-%u <= %u && elapsed(last_zero_window) == %f <= 0.7, continue\n", zero_window_start, min_next_seq_rem, 3*obj->squid_MSS, elapsed(last_zero_window));
                    continue;
                }
                char time_str[20];
                // log_info("[optack]: last_zero_window %s > 2s\n", print_chrono_time(last_zero_window, time_str));
                if((stall_seq == last_stall_seq && stall_port == last_stall_port && elapsed(last_restart) <= 1) || (stall_seq > last_stall_seq && elapsed(last_restart) <= 1)){
                    // log_debug("stall_seq == last_stall_seq == %u && elapsed(last_restart) == %f <= 1", stall_seq, elapsed(last_restart));
                    // printf("stall_seq == last_stall_seq == %u && elapsed(last_restart) == %f <= 1\n", stall_seq, elapsed(last_restart));
                    continue;
                }

                if(slowest_subconn->restart_counter >= 3){
                    if(slowest_subconn->restart_counter == 3){ //Giving up, retreat it as no overrun
                        opa_ack_start = obj->max_opt_ack;
                        slowest_subconn->next_seq_rem = obj->max_opt_ack;
                        slowest_subconn->last_data_received = std::chrono::system_clock::now();
                    }
                    slowest_subconn->restart_counter++;
                    continue;
                    
                    // if(obj->max_opt_ack != obj->ack_end){
                    //     for(int i = 0; i < 10; i++){
                    //         int adjust_rwnd_tmp = obj->get_ajusted_rwnd(opa_ack_dup_countdown);
                    //         if(adjust_rwnd_tmp > 0){
                    //             if(opa_ack_dup_countdown > mss){
                    //                 for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end();it++){
                    //                     if(elapsed(it->second->last_data_received) >= 1.5 && abs(int(it->second->next_seq_rem-stall_seq)) < 5*mss){
                    //                         for(int j = 0; j < 5; j++)
                    //                             obj->send_optimistic_ack(it->second, opa_ack_dup_countdown, adjust_rwnd_tmp);
                    //                         usleep(10000);
                    //                     }
                    //                 }
                    //                 opa_ack_dup_countdown -= mss;
                    //             }
                    //         }
                    //     }
                    // }
                    // else{
                    //     slowest_subconn->next_seq_rem = obj->max_opt_ack;
                    //     // slowest_subconn->last_data_received = std::chrono::system_clock::now();
                    //     // opa_ack_start = obj->max_opt_ack;
                    // }
                }

                if(!SPEEDUP_CONFIG && opa_ack_start != obj->ack_end && opa_ack_start <= stall_seq+10*mss){ //
                    // log_debug("not in SPEEDUP mode, opa_ack_start(%u) <= min_next_seq_rem(%u)+10*obj->squid_MSS", opa_ack_start, stall_seq);
                    // printf("not in SPEEDUP mode, opa_ack_start(%u) <= min_next_seq_rem(%u)+10*obj->squid_MSS\n", opa_ack_start, min_next_seq_rem);
                    continue;
                }
                // else{
                //     if(SPEEDUP_CONFIG)
                //         log_debug("in SPEEDUP mode");
                //     else if(opa_ack_start == obj->ack_end)
                //         log_debug("opa_ack_start(%u) == obj->ack_end(%u)", opa_ack_start, obj->ack_end);
                //     else if(opa_ack_start <= m)
                // }

                is_in_overrun = true;
                for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end();it++){
                    if(elapsed(it->second->last_data_received) >= 1.5 && abs(int(it->second->next_seq_rem-stall_seq)) < 5*mss){
                        if(it->second->restart_counter < 3){
                            for(int i = 0; i < 2; i++)
                                obj->send_optimistic_ack(it->second, it->second->next_seq_rem, obj->get_ajusted_rwnd(it->second->next_seq_rem));
                            sprintf(log, "%s, restart No.%u, send 2 acks %u to S%d, last received in case of ack being lost", log, it->second->restart_counter, it->second->next_seq_rem, it->second->local_port);
                        }
                        // else{
                        //     for(int i = 0; i < 10; i++)
                        //         obj->send_optimistic_ack(it->second, obj->max_opt_ack, obj->get_ajusted_rwnd(obj->max_opt_ack));
                        //     sprintf(log, "O: S%d stalls, restart No.%u, send 5 max_opt_acks %u to trigger retranx in case of bursty loss, ", stall_port, same_restart_cnt, obj->max_opt_ack);
                        //     usleep(10000);
                        // }
                    }
                }
                usleep(10000);//One RTT, wait for server to send out packets
                sprintf(log, "%s, current ack %u", log, opa_ack_start);
                uint restart_seq = slowest_subconn->restart_counter < 3? stall_seq / mss * mss + 1 + mss : obj->max_opt_ack;//Find the closest optimack we have sent
                opa_ack_start = restart_seq > mss? restart_seq - mss : 1; // - 5*mss to give the server time to send the following packets
                // if(restart_seq-last_restart_seq < 10*obj->squid_MSS)
                // if(restart_seq == last_restart_seq && elapsed(last_restart) <= 1)
                //     continue;
                // if(adjusted_rwnd <= 0 && zero_window_start <= min_next_seq_rem-obj->squid_MSS) //Is in zero window period, received upon the window end, not overrun
                //     continue;
                // if(elapsed(last_restart) <= 0)
                //     continue;
                    obj->overrun_cnt++;
                    if(stall_seq != last_stall_seq){
                        obj->overrun_penalty += elapsed(slowest_subconn->last_data_received);
                        same_restart_cnt = 0;
                    }
                    else{
                        obj->overrun_penalty += elapsed(last_restart);
                        if(stall_port == last_stall_port && stall_seq == last_stall_seq){
                            slowest_subconn->restart_counter++;
                            // if(same_restart_cnt == 6)
                            //     same_restart_cnt = 0;
                        }
                        // else
                        //     same_restart_cnt = 0;
                    }

                // }
                // else{
                    // sprintf(log, "O: recover from zero window, ");
                    // sprintf(log, "%scurrent ack %u, ", log, opa_ack_start);
                    // if (min_next_seq_rem > obj->squid_MSS)
                    //     opa_ack_start = min_next_seq_rem - obj->squid_MSS;
                    // else
                    //     opa_ack_start = 1;
                // }
                last_stall_port = stall_port;
                last_stall_seq = stall_seq;
                last_restart_seq = restart_seq;
                last_restart = std::chrono::system_clock::now();
                opa_ack_dup_countdown = obj->max_opt_ack;
                sprintf(log, "%s, restart at %u, zero_window_start %u, min_next_seq_rem %u\n", log, opa_ack_start, zero_window_start, min_next_seq_rem);
                log_info(log);
                printf(log);
            }
            last_overrun_check = std::chrono::system_clock::now();
            // if(elapsed(conn->last_data_received) >= 120){
            //     printf("Overrun bug occurs: S%u, %u\n", id, conn->next_seq_rem);
            //     exit(-1);
            // }
        }

        // usleep(10);
    }
 
    // conn->optim_ack_stop = 0;
    log_info("Optimistic ack ends");
    pthread_exit(NULL);
}


int Optimack::start_optim_ack_backup(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    subconn_infos[id]->opa_seq_start = opa_seq_start;
    subconn_infos[id]->opa_ack_start = opa_ack_start;
    subconn_infos[id]->opa_seq_max_restart = seq_max;
    subconn_infos[id]->opa_retrx_counter = 0;
    // subconn_infos[id]->payload_len = payload_len;
    // set to running
    subconn_infos[id]->optim_ack_stop = 0;

    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = id;
    ack_thr->obj = this;

    if (pthread_create(&(subconn_infos[id]->thread), NULL, selective_optimistic_ack, (void *)ack_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        printf("S%d: Fail to create optimistic_ack thread\n", id);
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // printf("S%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::start_optim_ack(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    subconn_infos[id]->opa_seq_start = opa_seq_start;
    subconn_infos[id]->opa_ack_start = opa_ack_start;
    subconn_infos[id]->opa_seq_max_restart = seq_max;
    subconn_infos[id]->opa_retrx_counter = 0;
    // subconn_infos[id]->payload_len = payload_len;
    // set to running
    subconn_infos[id]->optim_ack_stop = 0;

    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = id;
    ack_thr->obj = this;

    if (pthread_create(&(subconn_infos[id]->thread), NULL, full_optimistic_ack, (void *)ack_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        printf("S%d: Fail to create optimistic_ack thread\n", id);
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // printf("S%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::start_optim_ack_altogether(unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(!it->second->is_backup){
            it->second->opa_seq_start = opa_seq_start;
            it->second->opa_ack_start = opa_ack_start;
            it->second->opa_seq_max_restart = seq_max;
            it->second->opa_retrx_counter = 0;
            it->second->optim_ack_stop = 0;
        }
    }

    optim_ack_stop = 0;
    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = 0;
    ack_thr->obj = this;

    if (pthread_create(&optim_ack_thread, NULL, full_optimistic_ack_altogether, (void *)ack_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        printf("Fail to create optimistic_ack thread\n");
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // printf("S%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::restart_optim_ack(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer)
{
    struct subconn_info* subconn = subconn_infos[id];
    uint seq_rel = opa_ack_start - subconn->ini_seq_rem;

    subconn->optim_ack_stop = 1;
    // subconn->ack_pacing *= 2;
    pthread_join(subconn->thread, NULL);
    printf("S%d: Restart optim ack from %u\n\n", id, seq_rel);
    log_info("S%d: Restart optim ack from %u", id, seq_rel);
    start_optim_ack(id, opa_ack_start, opa_seq_start, payload_len, seq_max);//subconn->next_seq_rem
    timer += std::chrono::seconds(8);
}


void Optimack::log_seq_gaps(){
    // Print out all seq_gaps, in rows, transpose later
    printf("enter log_seq_gaps\n");
    // system("sudo kill -SIGKILL `pidof tcpdump`");
    // system("sudo kill -SIGKILL `pidof tshark`");
    system("bash /root/squid_copy/src/optimack/test/ks.sh loss_rate");
    system("bash /root/squid_copy/src/optimack/test/ks.sh mtr");
    // pclose(tcpdump_pipe);

    pthread_mutex_lock(&mutex_seq_next_global);
    uint seq_next_global_copy = seq_next_global;
    pthread_mutex_unlock(&mutex_seq_next_global);
    
    pthread_mutex_lock(&mutex_subconn_infos);
    int counts_len = seq_next_global_copy/1460+1;
    int* counts = (int*)malloc(counts_len*sizeof(int));
    memset(counts, 0, counts_len);
    map<string, int> lost_per_second;
    for(size_t j = 1; j < seq_next_global_copy; j+=1460){ //first row
        counts[j/1460] = 0;
    }
    // for(size_t k = 0; k < subconn_infos.size(); k++){
    //     size_t n = 1;
    //     pthread_mutex_lock(&subconn_infos[k].mutex_opa);
    //     for(size_t m = 0; m < subconn_infos[k].recved_seq.getIntervalList().size(); m++){
    //         for (; n < subconn_infos[k].seq_gaps[m].start; n+=1460);
    //         for (; n < subconn_infos[k].seq_gaps[m].end; n+=1460){
    //             counts[n/1460]++;
    //             // lost_per_second[subconn_infos[k].seq_gaps[m].timestamp]++;
    //         }
    //         int len = subconn_infos[k].seq_gaps[m].end - subconn_infos[k].seq_gaps[m].start;
    //         if(len < 100){
    //             // printf("len < 100, S%d: seq_gaps[%u] (%u, %u)\n", k, m, subconn_infos[k].seq_gaps[m].start, subconn_infos[k].seq_gaps[m].end);
    //         }
    //         lost_per_second[subconn_infos[k].seq_gaps[m].timestamp] += len;
    //         // fprintf(lost_per_second_file, "%s, 1\n", subconn_infos[k].seq_gaps[m].timestamp.c_str());
    //     }
    //     pthread_mutex_unlock(&subconn_infos[k].mutex_opa);
    // }

    // std::string line = "";
    // bool lost_on_all = false;
    // for(size_t j = 1; j < seq_next_global_copy; j+=1460){ //first row
    //     if(counts[j/1460] > subconn_infos.size()-9){
    //         lost_on_all = true;
    //         printf("Packet lost on all connections: %d\n", j/1460);
    //         break;
    //     }
    // }
    // lost_on_all = true;

    // char cmd[2000];
    // char* dir_name = cur_time.time_in_YYYY_MM_DD();
    // sprintf(cmd, "cd /root/rs/large_file_succ_rate/%s; echo >> seq_gaps_count_all.csv; echo Start: $(date -u --rfc-3339=second) >> seq_gaps_count_all.csv; cat seq_gaps_count.csv >> seq_gaps_count_all.csv",dir_name);
    // printf(cmd);
    // printf("\n");
    // system(cmd);    

    char time_str[30], tmp_str[1000];
    if(subconn_infos.size()){
        sprintf(tmp_str, "%s/%s", output_dir, info_file_name);
        FILE* info_file = fopen(tmp_str, "w");
        fprintf(info_file, "Start: %s\n", start_time);
        fprintf(info_file, "Stop: %s\n", time_in_HH_MM_SS_nospace(time_str));
        fprintf(info_file, "Duration: %.2fs\n", elapsed(start_timestamp));
        fprintf(info_file, "IP: %s\nPorts: ", g_remote_ip);
        for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
            fprintf(info_file, "%d, ", it->second->local_port);
        fprintf(info_file, "\n");
        fprintf(info_file, "Num of Conn: %d\n", CONN_NUM);
        fprintf(info_file, "ACK Pacing: %d\n", ACKPACING);
        if(RANGE_MODE)
            fprintf(info_file, "Mode: range\n");
        else if(BACKUP_MODE)
            fprintf(info_file, "Mode: backup\n");
        fprintf(info_file, "Overrun count: %d\n", overrun_cnt);
        fprintf(info_file, "Overrun penalty: %.2f\n", overrun_penalty);
        fprintf(info_file, "Range timeout count: %d\n", range_timeout_cnt);
        fprintf(info_file, "Range timeout penalty: %.2f\n", range_timeout_penalty);
        fprintf(info_file, "We2Squid loss count: %d\n", we2squid_lost_cnt);
        fprintf(info_file, "We2Squid loss penalty: %.2f\n", we2squid_penalty);
        if (RANGE_MODE){
            fprintf(info_file, "Packet lost on all: %d\n", all_lost_seq.total_bytes());
            fprintf(info_file, "%s\n", all_lost_seq.Intervals2str().c_str());
            fprintf(info_file, "Packet lost between us and squid: %d\n", we2squid_lost_seq.total_bytes());
            fprintf(info_file, "Range requested: %u\n", requested_bytes);
        }
        fprintf(info_file, "\n");
        is_nfq_full(info_file);
        fprintf(info_file,"\n");
        fprintf(info_file, "Request: %s\n", request);
        fprintf(info_file, "Response: %s\n", response);
        fclose(info_file);
    }

    // if(lost_on_all){
        // sprintf(tmp_str, "%s/seq_gaps_count_%s.csv", output_dir, time_in_HH_MM_SS_nospace(time_str));
        // seq_gaps_count_file = fopen(seq_gaps_count_file_name, "w");

        // is_nfq_full(seq_gaps_count_file);

        // fprintf(seq_gaps_count_file, "Start: %s\n", start_time);
        // fprintf(seq_gaps_count_file, "Stop: %s\n", time_in_HH_MM_SS_nospace(time_str));    
        // for(size_t j = 1; j < seq_next_global_copy; j+=1460){ //first row
        //     fprintf(seq_gaps_count_file, "%u, %d\n", j, counts[j/1460]);
        // }
        // fprintf(seq_gaps_count_file,"\n");
        // fflush(seq_gaps_count_file);

        // fprintf(seq_gaps_file, "Start: %s\n", cur_time.time_in_HH_MM_SS());
        // for(size_t k = 0; k < subconn_infos.size(); k++){
        //     if(!subconn_infos[k].seq_gaps.empty()){
        //         // printf("S%d: %s\n", k, Intervals2str(subconn_infos[k].seq_gaps).c_str());
        //         fprintf(seq_gaps_file, "S%d: %s\n", k, Intervals2str(subconn_infos[k].seq_gaps).c_str());
        //     }
        // }
        // fprintf(seq_gaps_file,"\n");
        // fflush(seq_gaps_file);

        // for(auto it = lost_per_second.begin(); it != lost_per_second.end(); it++){
        //     float packets_all_per_second = bytes_per_second[it->first.c_str()]*1.0/subconn_infos.begin()->payload_len;
        //     float packets_lost_per_second = it->second*1.0/subconn_infos.begin()->payload_len;
        //     fprintf(seq_gaps_count_file, "%s, %f, %f, %f\n", it->first.c_str(), packets_lost_per_second, packets_all_per_second, packets_lost_per_second/packets_all_per_second);

        // }
        // fprintf(seq_gaps_count_file,"\n\n");
        // fflush(seq_gaps_count_file);
        // fclose(seq_gaps_count_file);

        // std::string pcap_file = string(output_dir) + "/" + tcpdump_file_name;
        // std::string cmd_str = "screen -dmS tshark bash ~/squid_copy/src/optimack/test/parse_tshark.sh " + string(output_dir) + " " + tcpdump_file_name;
        // system(cmd_str.c_str());
        // cout << cmd_str << endl;
        // std::string cmd_str = "screen -dmS tshark bash -c 'tshark -r " + pcap_file + " -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y \"tcp.srcport eq 80 and tcp.len > 0\" > " + pcap_file + ".tshark";
        // std::string cmd_str = "screen -dmS cal_loss bash -c 'python ~/squid_copy/src/optimack/test/loss_rate_optimack_client.py " + string(output_dir) + "/" + tcpdump_file_name + " ";
        // for (size_t j = 0; j < subconn_infos.size(); j++)
        //     cmd_str += std::to_string(subconn_infos[j].local_port) + ",";
        // cmd_str += "; rm " + pcap_file + ";python ~/squid_copy/src/optimack/test/possibility.py " + string(output_dir) + " " + pcap_file + ".tshark" + "'";


    // }
    // else{
    //     sprintf(tmp_str, "cd %s; rm -v %s; rm -v %s;", output_dir, mtr_file_name, loss_file_name); //, tcpdump_file_name

    // sprintf(tmp_str, "cd %s; rm -v %s;", output_dir, tcpdump_file_name);
    // printf("%s\n", tmp_str);
    // system(tmp_str);

    // }
    


    // for(auto it = lost_per_second.begin(); it != lost_per_second.end(); it++){
    //     float packets_all_per_second = bytes_per_second[it->first.c_str()]*1.0/subconn_infos.begin()->payload_len;
    //     float packets_lost_per_second = it->second*1.0/subconn_infos.begin()->payload_len;
    //     fprintf(lost_per_second_file, "%s, %.0f, %.0f, %f\n", it->first.c_str(), packets_lost_per_second, packets_all_per_second, packets_lost_per_second/packets_all_per_second);

    // }
    // fflush(lost_per_second_file);
    // for(size_t k = 0; k < subconn_infos.size(); k++){
    //     line = "";
    //     size_t n = 1;
    //     for(size_t m = 0; m < subconn_infos[k].seq_gaps.size(); m++){
    //         for (; n < subconn_infos[k].seq_gaps[m].start; n+=1460)
    //             line += "0,";
    //         for (n =; n < subconn_infos[k].seq_gaps[m].end; n+=1460)
    //             line += std::to_string(k+1) + ",";
    //     }
    //     for (; n < seq_next_global; n+=1460)
    //         line += "0,";
    //     fprintf(seq_gaps_count_file, "%s\n", line.c_str());
    // }
    free(counts);
    counts = NULL;
    printf("Finished writing seq_gaps.\n");
    pthread_mutex_unlock(&mutex_subconn_infos);
}

void
Optimack::cleanup()
{
    log_info("enter cleanup");

    cb_stop = 1;

    log_seq_gaps();

    if(!overrun_stop){
        overrun_stop++;
        // pthread_join(overrun_thread, NULL);
        log_info("ask overrun_thread to exit");    
    }

    if(!range_stop){
        range_stop++;
        // pthread_join(range_thread, NULL);
        log_info("ask range_watch_thread to exit");    
    }

    if(!optim_ack_stop){
        optim_ack_stop++;
        // pthread_join(optim_ack_thread, NULL);
        log_info("ask optimack_altogether_thread to exit");    
    }

    if(BACKUP_MODE && backup_port && !subconn_infos[backup_port]->optim_ack_stop){
        subconn_infos[backup_port]->optim_ack_stop++;
        log_info("ask selective_optimack_thread to exit");
    }

    // stop other optimistic_ack threads and close fd
    // pthread_mutex_lock(&mutex_subconn_infos);
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    // // for (size_t i=0; i < subconn_infos.size(); i++) {
    //     // TODO: mutex?
    //     if (!it->second->optim_ack_stop) {
    //         it->second->optim_ack_stop++;
    //         pthread_join(it->second->thread, NULL);
    //         close(it->second->sockfd);
    //     }
    // }
    // log_info("NFQ %d all optimistic threads exited", nfq_queue_num);
    // pthread_mutex_unlock(&mutex_subconn_infos);

    pthread_mutex_lock(&mutex_subconn_infos);
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        free(it->second);
        it->second = NULL;
    }
    subconn_infos.clear();
    // clear iptables rules
    for (size_t i=0; i<iptables_rules.size(); i++) {
        exec_iptables('D', iptables_rules[i]);
        free(iptables_rules[i]);
        iptables_rules[i] = NULL;
    }
    iptables_rules.clear();
    request_recved = false;
    pthread_mutex_unlock(&mutex_subconn_infos);
}

Optimack::Optimack()
{
    iptables_rules.clear();
    subconn_infos.clear();
    bytes_per_second.clear();
    recv_buffer.clear();
    recved_seq.insertNewInterval(0,1);
    range_stop = -1;
}

Optimack::~Optimack()
{
    log_info("enter destructor");

    // stop nfq_loop thread
    // pthread_mutex_lock(&mutex_subconn_infos);
    if(nfq_stop)
        return;

    nfq_stop = 1;
    pthread_join(nfq_thread, NULL);
    log_info("NFQ %d nfq_thread exited", nfq_queue_num);

    cleanup();
    // pthread_mutex_unlock(&mutex_subconn_infos);

     // clear thr_pool
    thr_pool_destroy(pool);
    log_info("destroy thr_pool");
    teardown_nfq();
    log_info("teared down nfq");

    pthread_mutex_destroy(&mutex_seq_next_global);
    pthread_mutex_destroy(&mutex_subconn_infos);
    pthread_mutex_destroy(&mutex_optim_ack_stop);

    // fclose(seq_gaps_file);
    // fclose(seq_gaps_count_file);
}

void
Optimack::init()
{
    // init random seed
    srand(time(NULL));

    init_log();
    // init_exp_log("~/rs/exp.log");

    // initializing globals
    sockraw = open_sockraw();
    if (setsockopt(sockraw, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK)) < 0)
    {
        // debugs(0, DBG_CRITICAL, "couldn't set mark");
        exit(1);
    }

    int portno = 80;
    sockpacket = open_sockpacket(portno);
    if (sockpacket == -1) {
        // debugs(0, DBG_CRITICAL, "[main] can't open packet socket");
        exit(EXIT_FAILURE);
    }
    //if (signal(SIGINT, signal_handler) == SIG_ERR) {
        //log_error("register SIGINT handler failed.\n");
        //exit(EXIT_FAILURE);
    //}
    //if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        //log_error("register SIGSEGV handler failed.");
        //exit(EXIT_FAILURE);
    //}
    //if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        //log_error("register SIGPIPE handler failed.");
        //exit(EXIT_FAILURE);
    //}

    pool = thr_pool_create(4, 16, 300, NULL);
    if (!pool) {
            // debugs(0, DBG_CRITICAL, "couldn't create thr_pool");
            exit(1);                
    }

    char tmp_str[600], time_str[64];
    time_in_YYYY_MM_DD(time_str);
    // home_dir = getenv("HOME");

    strncpy(home_dir, "/root/", 6);
    home_dir[7] = 0;
    gethostname(hostname, 20);
    hostname[19] = 0;
    sprintf(output_dir, "%s/rs/ABtest_onerun/%s/", home_dir, time_str);
    sprintf(tmp_str, "mkdir -p %s", output_dir);
    system(tmp_str);
    printf("output dir: %s\n", output_dir);

    time_in_HH_MM_SS_nospace(start_time);

    // char log_file_name[100];
    // sprintf(log_file_name, "/root/off_packet_%s.csv", cur_time.time_in_HH_MM_SS());
    memset(tmp_str, 0, 600);
    sprintf(tmp_str, "%s/off_packet_%s.csv", output_dir, hostname);
    log_file = fopen(tmp_str, "w");
    fprintf(log_file, "time,off_packet_num\n");
    
    memset(tmp_str, 0, 600);
    sprintf(tmp_str, "%s/rwnd_%s.csv", output_dir, hostname);
    rwnd_file = fopen(tmp_str, "w");
    fprintf(rwnd_file, "time,rwnd\n");

    memset(tmp_str, 0, 600);
    sprintf(tmp_str, "%s/adjust_rwnd_%s.csv", output_dir, hostname);
    adjust_rwnd_file = fopen(tmp_str, "w");
    fprintf(adjust_rwnd_file, "time,adjust_rwnd\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/forward_seq_%s_%s.csv", output_dir, hostname, start_time);
    // forward_seq_file = fopen(tmp_str, "w");
    // fprintf(forward_seq_file, "time,fwd_seq_num\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/recv_seq_%s_%s.csv", output_dir, hostname, start_time);
    // recv_seq_file = fopen(tmp_str, "w");
    // fprintf(recv_seq_file, "time,port,recv_seq_num\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/processed_seq_%s_%s.csv", output_dir, hostname, start_time);
    // processed_seq_file = fopen(tmp_str, "w");
    // fprintf(processed_seq_file, "time,port,processed_seq_num\n");
   
    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/squid_ack_%s_%s.csv", output_dir, hostname, start_time);
    // ack_file = fopen(tmp_str, "w");
    // fprintf(ack_file, "time,ack_num\n");
    
    // sprintf(seq_gaps_count_file_name, "/root/rs/seq_gaps_count_file_%s.csv", cur_time.time_in_HH_MM_SS());
    sprintf(seq_gaps_count_file_name, "%s/seq_gaps_count_%s_%s.csv", output_dir, start_time, hostname);
    // seq_gaps_count_file = fopen(seq_gaps_count_file_name, "a");

    sprintf(info_file_name, "info_%s_%s.txt", hostname, start_time);

    sprintf(tmp_str, "%s/lost_per_second_%s.csv", output_dir, hostname);
    lost_per_second_file = fopen(tmp_str, "a");

    last_speedup_time = last_rwnd_write_time = last_restart_time = last_ack_time = std::chrono::system_clock::now();

    optim_ack_stop = nfq_stop = overrun_stop = cb_stop = range_stop = -1;

    sprintf(tcpdump_file_name, "tcpdump_%s.pcap", start_time);
    sprintf(tmp_str,"tcpdump -w %s/%s -s 96 tcp &", output_dir, tcpdump_file_name);
    // sprintf(tmp_str,"tcpdump -w %s/%s -s 96 tcp src port 80 &", output_dir, tcpdump_file_name);
    // system(tmp_str);

    // printf("test openssl-bio-fetch: %d\n", test_include());
    // sprintf(tcpdump_file_name, "tcpdump_%s.tshark", start_time);
    // sprintf(tmp_str, "tshark -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y 'tcp.srcport eq 80 and tcp.len > 0' > %s/%s &", output_dir, tcpdump_file_name);
    // system(tmp_str);
    subconn_infos.clear();
}

void log_seq(FILE* file, uint seq){
    // return;
    char time_str[30];
    fprintf(file, "%f, %u\n", get_current_epoch_time_nanosecond(), seq);
}

void log_seq(FILE* file, int port, uint seq){
    // return;
    fprintf(file, "%f, %d, %u\n", get_current_epoch_time_nanosecond(), port, seq);
}

int 
Optimack::setup_nfq(unsigned short id)
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        // debugs(0, DBG_CRITICAL,"error during nfq_open()");
        return -1;
    }

    // debugs(0, DBG_CRITICAL,"unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_unbind_pf()");
        return -1;
    }

    // debugs(0, DBG_CRITICAL,"binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    nfq_queue_num = id;
    // debugs(0, DBG_CRITICAL,"binding this socket to queue " << nfq_queue_num);
    g_nfq_qh = nfq_create_queue(g_nfq_h, nfq_queue_num, &cb, (void*)this);
    if (!g_nfq_qh) {
        // debugs(0, DBG_CRITICAL,"error during nfq_create_queue()");
        return -1;
    }
    // debugs(0, DBG_CRITICAL,"nfq queue handler: " << g_nfq_qh);

    // debugs(0, DBG_CRITICAL,"setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        // debugs(0, DBG_CRITICAL,"can't set packet_copy mode");
        return -1;
    }

    unsigned int bufsize = 0x3fffffff, rc = 0;//
    if (nfq_set_queue_maxlen(g_nfq_qh, bufsize/1024) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    // for (; ; bufsize-=0x1000){
    //     rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    //     printf("Buffer size %x wanted %x\n", rc, bufsize);
    //     if (rc == bufsize*2)
    //         break;
    // }
    rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    log_info("Buffer size %x wanted %x", rc, bufsize*2);
    if(rc != bufsize*2){
        exit(-1);
    }

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int 
Optimack::setup_nfqloop()
{
    // pass the Optimack obj
    nfq_stop = cb_stop = 0;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, (void*)this) != 0) {
        // debugs(1, DBG_CRITICAL,"Fail to create nfq thread.");
        return -1;
    }
    return 0;
}

int 
Optimack::teardown_nfq()
{
    log_info("unbinding from queue %d", nfq_queue_num);
    if (nfq_destroy_queue(g_nfq_qh) != 0) {
        log_error("error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    // debugs(0, DBG_CRITICAL,"unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    // debugs(0, DBG_CRITICAL,"closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_close()");
        return -1;
    }

    return 0;
}

static int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    Optimack* obj = (Optimack*)data;
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    if(obj->cb_stop)
        return -1;

    struct myiphdr *iphdr = ip_hdr(packet);
    // struct mytcphdr *tcphdr = tcp_hdr(packet);
    //unsigned char *payload = tcp_payload(thr_data->buf);
    // unsigned int payload_len = packet_len - iphdr->ihl*4 - tcphdr->th_off*4;
    char sip[16], dip[16];
    ip2str(iphdr->saddr, sip);
    ip2str(iphdr->daddr, dip);

    //char log[LOGSIZE];
    //sprintf(log, "%s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", sip, ntohs(tcphdr->th_sport), dip, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
    //debugs(0, DBG_CRITICAL, log);

    struct thread_data* thr_data = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (!thr_data)
    {
        // debugs(0, DBG_CRITICAL, "cb: error during thr_data malloc");
        return -1;
    }
    memset(thr_data, 0, sizeof(struct thread_data));

    // sanity check, could be abbr later
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    // printf("P%d: hook %d\n", ph->packet_id, ph->hook);
    if (!ph) {
        // debugs(0, DBG_CRITICAL,"nfq_get_msg_packet_hdr failed");
        return -1;
    }

    thr_data->pkt_id = htonl(ph->packet_id);
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len+1);
    thr_data->obj = obj;
    if (!thr_data->buf){
            // debugs(0, DBG_CRITICAL, "cb: error during malloc");
            return -1;
    }
    memcpy(thr_data->buf, packet, packet_len);
    thr_data->buf[packet_len] = 0;
    // printf("in cb: packet_len %d\nthr_data->buf", packet_len);
    // hex_dump(thr_data->buf, packet_len);
    // printf("packet:\n");
    // hex_dump(packet, packet_len);

    // pool_handler((void *)thr_data);
    if(thr_pool_queue(obj->pool, pool_handler, (void *)thr_data) < 0) {
        // debugs(0, DBG_CRITICAL, "cb: error during thr_pool_queue");
        return -1;
    }
    return 0;
}

void Optimack::print_seq_table(){

    printf("%12s%12s","ID","squid");
    for(uint i = 0; i < subconn_count; i++){
        printf("%12u", i);
    }
    printf("\n");

    printf("%12s%12u","Port",cur_ack_rel);
    
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12u", it->second->local_port);
    }
    printf("\n");

    printf("%12s%12u", "next_seq_rem", recved_seq.getFirstEnd());
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12u", it->second->next_seq_rem);
    }
    printf("\n");

    // printf("%12s%12u%12u", "rwnd", rwnd, adjusted_rwnd);
    // for (auto const& [port, subconn] : subconn_infos){
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    //     printf("%12d", it->second->rwnd);
    // }
    printf("\n");

    printf("SACK: ");
    sack_list.printIntervals();

    printf("Recv_seq: ");
    recved_seq.printIntervals();

    if(BACKUP_MODE){
        printf("Backup: ");
        subconn_infos[backup_port]->recved_seq.printIntervals();
    }
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    //     it->second->recved_seq.printIntervals();
    // }
    // for(uint i = 0; i < num_conns; i++){
    //     printf("%12u", subconn_infos[i].local_port);
    // }
    // printf("\n");


    // printf("%12s%12u", "next_seq_rem", recved_seq.getFirstEnd_withLock());
    // for(uint i = 0; i < num_conns; i++){
    //     printf("%12u", subconn_infos[i].next_seq_rem);
    // }
    // printf("\n");

    // printf("%12s%12u", "rwnd", rwnd);
    // for(uint i = 0; i < num_conns; i++){
    //     printf("%12d", subconn_infos[i].rwnd);
    // }
    // printf("\n");
    // printf("\n");
}

const char header_field[] = "HTTP/1.1 206";
const char range_field[] = "Content-Range: bytes ";
const char tail_field[] = "\r\n\r\n";
const char keep_alive_field[] = "Keep-Alive: ";
const char max_field[] = "max=";

struct http_header {
    int parsed;
    int remain;
    int start;
    int end;
};

int
parse_response(http_header *head, char *response, int unread)
{
    char *recv_end = response + unread;
    char *parse_head;
    if (head->parsed) {
        log_debug("[Range] error: header should have been parsed");
        return -1;
    }
    // check header
    parse_head = std::search(response, recv_end, header_field, header_field+12);
    if (parse_head < recv_end) {
        // check range
        parse_head = std::search(parse_head, recv_end, range_field, range_field+21);
        if (parse_head < recv_end) {
            parse_head += 21;
            if(parse_head < recv_end){
                head->start = (int)strtol(parse_head, &parse_head, 10);
                parse_head++;
                if(parse_head < recv_end){
                    head->end = (int)strtol(parse_head, &parse_head, 10);
                    head->remain = head->end - head->start + 1;
                    parse_head = std::search(parse_head, recv_end, tail_field, tail_field+4);
                    if (parse_head < recv_end) {
                        parse_head += 4;
                        head->parsed = 1;
                        log_debug("[Range] Header received %d - %d", head->start, head->end);
                        return parse_head-response;
                    }
                }
            }
        }
    }
    return 0;
}

void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    range_sockfd_old = range_sockfd;
    range_sockfd = -1;
    memset(header, 0, sizeof(http_header));
    consumed = unread = parsed = recv_offset = unsent = 0;
}


int process_range_rv(char* response, int rv, Optimack* obj, subconn_info* subconn, std::vector<Interval> range_job_vector, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    if (rv > MAX_RANGE_SIZE)
        printf("[Range]: rv %d > MAX %d\n", rv, MAX_RANGE_SIZE);

    char data[MAX_RANGE_SIZE+1];
    unread += rv;
    consumed = 0;
    while (unread > 0) {
        if (!header->parsed) {
            // parse header
            parsed = parse_response(header, response+consumed, unread);
            if (parsed <= 0) {
                // incomplete http header
                // keep receiving and parse in next response
                memmove(response, response+consumed, unread);
                recv_offset += unread;
                log_error("[Range] incomplete http header, len %d\n", unread);
                printf("[Range] incomplete http header, len %d\n", unread);
                break;
            }
            else {
                // parser
                // headerBuf.assign(response+consumed, unread);
                // rp.parse(headerBuf);
                // printf("[Range]: headBlockSize %d Parsed %d StatusCode %d\n", rp.headerBlockSize(), parsed, rp.parseStatusCode);
                // src/http/StatusCode.h

                recv_offset = 0;
                consumed += parsed;
                unread -= parsed;
            }
        }
        else {
            // collect data
            if (header->remain <= unread) {
                // we have all the data
                // printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->end, header->remain, unread);
                log_error("[Range] data retrieved %d - %d", header->start, header->end);
                printf("[Range] data retrieved %d - %d\n", header->start, header->end);

                memcpy(data, response+consumed, header->remain);
                header->parsed = 0;
                unread -= header->remain;
                consumed += header->remain;
                unsent = header->end - header->start + 1;
                // parser
                // rp.clear();
                /*
                * TODO: send(buf=data, size=unsent) to client here
                * remove interval gaps (header->start, header->end) here
                */
                // range_job->removeInterval(header->start, header->end);
                log_error("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                printf("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                obj->ranges_sent.removeInterval(header->start, header->end);
                log_error("After removing [%u, %u], %s", header->start, header->end, obj->ranges_sent.Intervals2str().c_str());
                printf("After removing [%u, %u], %s\n", header->start, header->end, obj->ranges_sent.Intervals2str().c_str());
            }
            else {
                // still need more data
                // we can consume and send all unread data
                printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->start+unread, header->remain, unread);
                log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start, header->start+unread, header->remain, unread);
                memcpy(data, response+consumed, unread);
                header->remain -= unread;
                consumed += unread;
                unsent = unread;
                unread = 0;
                /*
                * TODO:
                * remove interval gaps (header->start, header->start+unread-1) here
                */
                // range_job->removeInterval(header->start, header->start+unsent);
                log_error("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                printf("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                obj->ranges_sent.removeInterval(header->start, header->start+unsent);
                log_error("After removing [%u, %u], %s", header->start, header->start+unsent, obj->ranges_sent.Intervals2str().c_str());
                printf("After removing [%u, %u], %s\n", header->start, header->start+unsent, obj->ranges_sent.Intervals2str().c_str());
            }

            int sent, packet_len;
            uint ack, seq, seq_rel;
            for (sent=0; unsent > 0; sent += packet_len, unsent -= packet_len) {
                packet_len = unsent >= obj->squid_MSS? obj->squid_MSS : unsent;

                // obj->ranges_sent.removeInterval_withLock(header->start+sent, header->start+sent+packet_len);
                ack = subconn->ini_seq_loc + subconn->next_seq_loc;
                seq_rel = 1 + obj->response_header_len + header->start + sent;
                seq = subconn->ini_seq_rem +  seq_rel; // Adding the offset back
                // send_ACK_payload(obj->g_local_ip, obj->g_remote_ip, obj->squid_port, obj->g_remote_port, (u_char*)(data + sent), packet_len, ack, seq);
                // log_error("range_recv:2132: recved_seq - lock"); 
                obj->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+packet_len);
                log_debug("[Range] insert [%u,%u] to recved_seq, after %s", seq_rel, seq_rel+packet_len, obj->recved_seq.Intervals2str().substr(0,490).c_str());
                // log_error("range_recv:2132: recved_seq - unlock"); 
                // log_error("range_recv:2132: all_lost_seq - lock"); 
                obj->all_lost_seq.insertNewInterval_withLock(seq_rel, seq_rel+packet_len);
                // log_error("range_recv:2132: all_lost_seq - unlock"); 
                obj->send_data_to_squid(seq_rel, (u_char*)(data + sent), packet_len);
                log_debug("[Range] insert [%u,%u] to all_lost_seq", seq_rel, seq_rel+packet_len);
                // obj->insert_to_recv_buffer_withLock(seq_rel, (u_char*)data+sent, packet_len);
                log_debug("[Range] retrieved and sent seq %x(%u) ack %x(%u)", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc);
                printf("[Range] retrieved and sent seq %x(%u) ack %x(%u) len %u\n", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc, packet_len);
            }
            obj->send_out_of_order_recv_buffer_withLock(seq_rel + packet_len);
            recv_offset = 0;
            header->start += sent;
        }
    }
    if (unread < 0){
        log_debug("[Range] error: unread < 0");
        return -1;
    }
    if(recv_offset > MAX_RANGE_SIZE){
        printf("recv_offset %d > MAX_RANGE_SIZE %u\n", recv_offset, MAX_RANGE_SIZE);
        return -1;
    }
    return 0;
}


void*
range_watch(void* arg)
{
    printf("[Range]: range_watch thread starts\n");

    int rv, range_sockfd, range_sockfd_old, erase_count = 0;
    char response[MAX_RANGE_SIZE+1];

    Optimack* obj = ((Optimack*)arg);
    range_sockfd = -1;

    pthread_mutex_t *mutex = &(obj->mutex_seq_gaps);
    subconn_info* subconn = (obj->subconn_infos.begin()->second);

    std::vector<Interval>& range_job_vector = obj->ranges_sent.getIntervalList();
    pthread_mutex_t* p_mutex_range_job_vector = obj->ranges_sent.getMutex();

    int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0, packet_len=0;
    http_header* header = (http_header*)malloc(sizeof(http_header));
    memset(header, 0, sizeof(http_header));
    // parser
    // Http1::RequestParser rp;
    // SBuf headerBuf;

    // int fd = open("/dev/null", O_RDONLY);
    // dup2(fd, STDIN_FILENO);
    // close(fd);
    // for(int fd=0; fd < 3; fd++){
    //     int nfd;
    //     nfd = open("/dev/null", O_RDWR);

    //     if(nfd<0) /* We're screwed. */
    //     continue;

    //     if(nfd==fd)
    //     continue;

    //     dup2(nfd, fd);
    //     if(nfd > 2)
    //     close(nfd);
    // }

    while(!obj->range_stop) {

        // printf("try_for_gaps_and_request\n");
        obj->try_for_gaps_and_request();

        // printf("enter range loop\n");
        if(range_job_vector.size() == 0){
            // printf("range_job_vector.size() == 0\n");
            continue;
        }

        // printf("enter range_sockfd <= 0");
        if(range_sockfd <= 0 || obj->range_request_count >= 95 || erase_count >= 5){
            //clear all sent timestamp, to resend it
            // pthread_mutex_lock(p_mutex_range_job_vector);
restart:
            for (auto it = range_job_vector.begin(); it != range_job_vector.end();it++){
                it->sent_epoch_time = 0;
            }
            // pthread_mutex_unlock(p_mutex_range_job_vector);

            range_sockfd = obj->establish_tcp_connection(range_sockfd_old);
            close(range_sockfd_old);
            printf("[Range] New conn, fd %d, port %d\n", range_sockfd, obj->get_localport(range_sockfd));
            log_info("[Range] New conn, fd %d, port %d\n", range_sockfd, obj->get_localport(range_sockfd));
            obj->range_request_count = 0;
            erase_count = 0;
        }
        if(range_sockfd <= 0){ //TODO: remove ranges_sent?{
            perror("Can't create range_sockfd, range thread break\n");
            break;
        }

        //Check if any more unsent range and sent
        // printf("Check if any more unsent range and sent\n");
        // pthread_mutex_lock(p_mutex_range_job_vector);
        for (auto it = range_job_vector.begin(); it != range_job_vector.end();){
        // for(auto it : range_job->getIntervalList()) {
            // printf("[Range] Resend bytes %d - %d\n", it.start, it.end);
            if (obj->cur_ack_rel >= it->end+obj->response_header_len+1){
                erase_count++;
                log_info("[Range] cur_ack_rel %u >= it->end %u, delete\n", obj->cur_ack_rel, it->end+obj->response_header_len+1);
                printf("[Range] cur_ack_rel %u >= it->end %u, delete, erase count %d\n", obj->cur_ack_rel, it->end+obj->response_header_len+1, erase_count);
                // printf("before erase it: [%u, %u]\n", it->start, it->end);
                range_job_vector.erase(it++);
                if(!range_job_vector.size())
                    break;
                // printf("after erase it: [%u, %u]\n", it->start, it->end);
                continue;
            }
            if(!it->sent_epoch_time){
                obj->send_http_range_request(range_sockfd, *it);
                it->sent_epoch_time = get_current_epoch_time_second();
                // printf("[Range]: sent range[%u, %u]\n", it->start+obj->response_header_len+1, it->end+obj->response_header_len+1);
            }
            else if (get_current_epoch_time_nanosecond() - it->sent_epoch_time >= 20){//timeout, send it again
                double delay = get_current_epoch_time_nanosecond() - it->sent_epoch_time;
                obj->range_timeout_cnt++;
                obj->range_timeout_penalty += delay;
                log_info("[Range] [%u, %u] timeout %.2f, close and restart\n", it->start+obj->response_header_len+1, it->end+obj->response_header_len+1, delay);
                printf("[Range] [%u, %u] timeout %.2f, close and restart\n", it->start+obj->response_header_len+1, it->end+obj->response_header_len+1, delay);
                // close(range_sockfd);
                cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
                // range_sockfd_old = range_sockfd;
                // range_sockfd = -1;
                break;
            }
            it++;

        }
        // pthread_mutex_unlock(p_mutex_range_job_vector);

        // Receiving packet
        // printf("Receiving packet\n");
        memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset);
        rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);

        if (rv > 0) {
            log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
            printf("[Range] recved %d bytes, hand over to process_range_rv\n", rv);
            process_range_rv(response, rv, obj, subconn, range_job_vector, header, consumed, unread, parsed, recv_offset, unsent);
        }
        else if (rv == 0){
            log_debug("[Range] ret %d, sockfd %d closed ", rv, range_sockfd);
            printf("[Range] ret %d, sockfd %d closed\n", rv, range_sockfd);
            // close(range_sockfd);
            cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
            // range_sockfd_old = range_sockfd;
            // range_sockfd = -1;
            printf("closed range_sockfd %d\n", range_sockfd);
        }
        else if (!(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)){
            log_debug("[Range] error: ret %d errno %d", rv, errno);
            printf("[Range] error: ret %d errno %d\n", rv, errno);
            // close(range_sockfd);
            cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
            // range_sockfd_old = range_sockfd;
            // range_sockfd = -1;
        }
        usleep(100);
    }
    free(header);
    header = NULL;

    printf("[Range]: range_watch thread exits...\n");
    pthread_exit(NULL);
}


void* overrun_detector(void* arg){
    Optimack* obj = (Optimack* )arg;
    // std::chrono::time_point<std::chrono::system_clock> *timers = new std::chrono::time_point<std::chrono::system_clock>[num_conns];

    sleep(2);//Wait for the packets to come
    log_info("Start overrun_detector thread");


    auto last_print_seqs = std::chrono::system_clock::now();
    while(!obj->overrun_stop){
        if(is_timeout_and_update(last_print_seqs, 2)){
            obj->print_seq_table();
            // obj->is_nfq_full(stdout);
            obj->print_ss(stdout);
            printf("\n");
        }

        // if (RANGE_MODE) {
        //     // if(is_timeout_and_update(obj->last_ack_time, 2))
        //     obj->try_for_gaps_and_request();
        // }
        usleep(10);
    }
    // free(timers);
    log_info("overrun_detector thread ends");
    printf("overrun_detector thread ends\n");
    pthread_exit(NULL);
}

void Optimack::try_for_gaps_and_request(){
    uint last_recv_inorder;
    if(last_ack_epochtime > last_inorder_data_epochtime && elapsed(last_ack_time) > 1.5){
        // if(!resend_cnt){
        //     if(cur_ack_rel < recved_seq.getFirstEnd()){
        //         resend_cnt++;
        //         printf("last_ack_time > 2, resend recv_buffer, cur_ack_rel %u < firstEnd %u\n", cur_ack_rel, recved_seq.getFirstEnd());
        //         log_info("last_ack_time > 2, resend recv_buffer, cur_ack_rel %u < firstEnd %u", cur_ack_rel, recved_seq.getFirstEnd());
        //         send_out_of_order_recv_buffer_withLock(cur_ack_rel);
        //         // send_out_of_order_recv_buffer_withLock(cur_ack_rel, recved_seq.getFirstEnd(), 2);
        //     }
        // }

        if(elapsed(last_ack_time) > MAX_STALL_TIME){
            // char time_str[20] = "";
            // printf("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
            // log_info("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
            
        }
        // if(cur_ack_rel < recved_seq.getFirstEnd() && cur_ack_rel < get_min_next_seq_rem()){
            // remove_recved_recv_buffer(cur_ack_rel);
            // last_recv_inorder = recved_seq.getFirstEnd();
            // pthread_mutex_lock(sack_list.getMutex());
            // if(sack_list.size() > 0){
            //     // printf("recved_seq[0].end %u, sack_list[0].start %u\n", last_recv_inorder, sack_list.getElem_withLock(0,true));
            //     // print_ss(stdout);
            //     auto sack_interval_list = sack_list.getIntervalList();
            //     we2squid_loss_and_insert(cur_ack_rel, sack_interval_list.at(0).start-1);

            //     uint min_seq = get_min_next_seq_rem();
            //     for(int i = 1; i < sack_interval_list.size(); i++){
            //         if(min_seq >= sack_interval_list.at(i-1).end){
            //             Interval we2squid_range2(sack_interval_list.at(i-1).end, sack_interval_list.at(i).start-1);
            //             if(get_lost_range(&we2squid_range2) >= 0){
            //                 ranges_sent.insert_withLock(we2squid_range2);
            //                 log_info("we2squid lost: request range[%u, %u]", we2squid_range2.start, we2squid_range2.end);
            //             }
            //         }
            //     }
            //     pthread_mutex_unlock(sack_list.getMutex());
            // }
            // else{
            //     pthread_mutex_unlock(sack_list.getMutex());
            //     we2squid_loss_and_insert(cur_ack_rel, last_recv_inorder-1);
            // }
        // }
    }

    if(check_packet_lost_on_all_conns(recved_seq.getFirstEnd())){
        // printf("[Range]: lost on all conns\n");
        // lost_range [recved_seq[0].end, recved_seq[1].end]
        // Interval lost_range = get_lost_range();
        uint first_out_of_order = recved_seq.getElem_withLock(1,true);// ;getIntervalList().at(1).start
        if(first_out_of_order){
            Interval lost_all_range(recved_seq.getFirstEnd(), first_out_of_order);
            if(get_lost_range(&lost_all_range) >= 0){
                ranges_sent.insert(lost_all_range);
                log_info("lost on all: request range[%u, %u]",lost_all_range.start+ response_header_len + 1, lost_all_range.end + response_header_len + 1);
                // start_range_recv(intervallist);
            }
        }
    }

    // if(recved_seq.size() > 1){
    //     pthread_mutex_t* p_mutex_recved_seq = recved_seq.getMutex();
    //     // pthread_mutex_lock(p_mutex_recved_seq);
    //     if(recved_seq.size() > 1){
    //         for (auto prev = recved_seq.getIntervalList().begin(), cur = ++recved_seq.getIntervalList().begin(); cur != recved_seq.getIntervalList().end(); prev = cur, cur++){
    //             if(!check_packet_lost_on_all_conns(prev->end))
    //                 break;

    //             uint lost_end = cur->start;
    //             if(lost_end){
    //                 Interval lost_all_range(prev->end, lost_end-1);
    //                 if(get_lost_range(&lost_all_range) >= 0){
    //                     ranges_sent.insert_withLock(lost_all_range);
    //                     // printf("[Range]: insert [%u,%u] to ranges_sent\n", lost_all_range.start, lost_all_range.end);
    //                     log_info("lost on all: request range[%u, %u]",lost_all_range.start+ response_header_len + 1, lost_all_range.end + response_header_len + 1);
    //                 }
    //             }
    //         }
    //     }
    //     pthread_mutex_unlock(p_mutex_recved_seq);
    // }
}

// void Optimack::try_for_gaps_and_request(){
//     uint last_recv_inorder;
//     IntervalList* lost_ranges = new IntervalList();
//     if(elapsed(last_ack_time) > 10){
//         if(elapsed(last_ack_time) > MAX_STALL_TIME){
//             char time_str[20] = "";
//             printf("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
//             log_info("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
//             exit(-1);
//         }
//         if(cur_ack_rel < recved_seq.getFirstEnd_withLock() && cur_ack_rel < get_min_next_seq_rem()){
//             last_recv_inorder = recved_seq.getFirstEnd_withLock();
//             // IntervalList* intervallist = NULL;
//             pthread_mutex_lock(sack_list.getMutex());
//             if(sack_list.size() > 0){
//                 // printf("recved_seq[0].end %u, sack_list[0].start %u\n", last_recv_inorder, sack_list.getElem_withLock(0,true));
//                 // print_ss(stdout);
//                 auto sack_interval_list = sack_list.getIntervalList();
//                 we2squid_loss_and_start_range_recv(cur_ack_rel, sack_interval_list.at(0).start-1, lost_ranges);

//                 uint min_seq = get_min_next_seq_rem();
//                 for(int i = 1; i < sack_interval_list.size(); i++){
//                     if(min_seq >= sack_interval_list.at(i-1).end){
//                         Interval we2squid_range2(sack_interval_list.at(i-1).end, sack_interval_list.at(i).start-1);
//                         if(get_lost_range(&we2squid_range2) >= 0){
//                             lost_ranges->insertNewInterval(we2squid_range2);
//                             log_info("we2squid lost: request range[%u, %u]", we2squid_range2.start, we2squid_range2.end);
//                         }
//                     }
//                 }
//             }
//             else{
//                 we2squid_loss_and_start_range_recv(cur_ack_rel, last_recv_inorder-1, lost_ranges);
//             }
//             pthread_mutex_unlock(sack_list.getMutex());
//         }
//     }

//     if(check_packet_lost_on_all_conns(recved_seq.getFirstEnd_withLock())){
//         // printf("[Range]: lost on all conns\n");
//         // lost_range [recved_seq[0].end, recved_seq[1].end]
//         // Interval lost_range = get_lost_range();
//         uint first_out_of_order = recved_seq.getElem_withLock(1,true);
//         if(first_out_of_order){
//             Interval lost_all_range(recved_seq.getFirstEnd_withLock(), first_out_of_order-1);
//             if(get_lost_range(&lost_all_range) >= 0){
//                 lost_ranges->insertNewInterval(lost_all_range);
//                 // all_lost_seq.insertNewInterval_withLock(lost_all_range);
//                 log_info("lost on all: request range[%u, %u]",lost_all_range.start+ response_header_len + 1, lost_all_range.end + response_header_len + 1);
//                 // start_range_recv(intervallist);
//             }
//         }
//     }
    
//     if(lost_ranges->size())
//         start_range_recv(lost_ranges);
//     else
//         delete lost_ranges;
// }

void Optimack::we2squid_loss_and_insert(uint start, uint end){
    Interval we2squid_range(start, end);
    if(get_lost_range(&we2squid_range) >= 0){
        printf("[Warn]: tool to squid packet loss! cur_ack_rel %u - last_recv_inorder %u\n", start, end);
        log_info("[Warn]: tool to squid packet loss! cur_ack_rel %u - last_recv_inorder %u", start, end);

        ranges_sent.insert_withLock(we2squid_range);
        start = we2squid_range.start;
        end = we2squid_range.end;
        if(we2squid_lost_seq.checkAndinsertNewInterval_withLock(start, end)){
            we2squid_lost_cnt++;
            we2squid_penalty += elapsed(last_ack_time);
        }
        log_info("we2squid lost: request range[%u, %u]", start, end);
    }
}

void Optimack::we2squid_loss_and_start_range_recv(uint start, uint end, IntervalList* intvl_list){
    Interval we2squid_range(start, end);
    if(get_lost_range(&we2squid_range) >= 0){
        printf("[Warn]: tool to squid packet loss! cur_ack_rel %u - last_recv_inorder %u\n", start, end);
        log_info("[Warn]: tool to squid packet loss! cur_ack_rel %u - last_recv_inorder %u", start, end);

        intvl_list->insertNewInterval(we2squid_range);
        start = we2squid_range.start;
        end = we2squid_range.end;
        if(we2squid_lost_seq.checkAndinsertNewInterval_withLock(start, end)){
            we2squid_lost_cnt++;
            we2squid_penalty += elapsed(last_ack_time);
        }
        log_info("we2squid lost: request range[%u, %u]", start, end);
    }
}


uint Optimack::get_min_next_seq_rem(){
    uint min_next_seq_rem = -1;
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(!it->second->is_backup && !it->second->fin_or_rst_recved){
            min_next_seq_rem = std::min(min_next_seq_rem, it->second->next_seq_rem);
        }
    }
    return min_next_seq_rem;
}



bool Optimack::check_packet_lost_on_all_conns(uint last_recv_inorder){
    // uint seq_recved_global = recved_seq.getFirstEnd_withLock();//TODO: Or ?  cur_ack_rel
    if (recved_seq.size() < 2)
        return false;

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        // log_info("first: recved_seq.lastend %u, last_recv_inorder %u", it->second->recved_seq.getLastEnd(), last_recv_inorder);
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->next_seq_rem <= last_recv_inorder){
            // log_info("<=, return false\n");
            return false;
        }
        // else
        //     printf(">, continue\n");
    }
    usleep(800000);
    char tmp[1000] = {0};
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        // sprintf(tmp, "%s %d:%u", tmp, it->second->id, it->second->next_seq_rem);
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->next_seq_rem <= last_recv_inorder){
            log_info("second: %s, <=, return false", tmp);
            return false;
        }
    }
    // sprintf(tmp, "%s recved_seq.FirstEnd:%u", tmp, recved_seq.getFirstEnd());
    // log_info("lost on all: %s", tmp);
    return true;
}

int Optimack::get_lost_range(Interval* intvl)
{
    // uint min_next_seq_rem = recved_seq.getElem_withLock(1, true);
    // // recved_seq.printIntervals();
    // if(min_next_seq_rem == 0)
    //     min_next_seq_rem = -1;
    
    // // for (size_t i = 1; i < num_conns; i++)
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
    //     min_next_seq_rem = std::min(min_next_seq_rem, it->second->next_seq_rem);
    
    // if(min_next_seq_rem == -1)
    //     return Interval(0,0);
    uint start = intvl->start, end = intvl->end;
    if(start == 0 || end == 0 || start <= response_header_len+1 || end <= response_header_len+1 || !response_header_len)
        return -1;

    // check if the range has already been sent
    IntervalList lost_range;
    lost_range.clear();
    lost_range.insertNewInterval(start-response_header_len-1, end-response_header_len-1);
    lost_range.substract(&ranges_sent);
    if(lost_range.size()){
        intvl->start = lost_range.getIntervalList().at(0).start;
        intvl->end = lost_range.getIntervalList().at(0).end;
        return 0;
    }
    else
        return -1;
}

// IntervalList* Optimack::get_lost_range(uint start, uint end)
// {
//     // uint min_next_seq_rem = recved_seq.getElem_withLock(1, true);
//     // // recved_seq.printIntervals();
//     // if(min_next_seq_rem == 0)
//     //     min_next_seq_rem = -1;
    
//     // // for (size_t i = 1; i < num_conns; i++)
//     // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
//     //     min_next_seq_rem = std::min(min_next_seq_rem, it->second->next_seq_rem);
    
//     // if(min_next_seq_rem == -1)
//     //     return Interval(0,0);

//     if(start == 0 || end == 0 || start < response_header_len || end < response_header_len)
//         return NULL;

//     // check if the range has already been sent
//     IntervalList* lost_range = new IntervalList();
//     lost_range->clear();
//     lost_range->insertNewInterval(start-response_header_len-1, end-response_header_len-1);
//     lost_range->substract(&ranges_sent);
//     if(lost_range->size()){
//         return lost_range;
//     }
//     else
//         return NULL;
// }



// struct Range_Args{
//     Optimack* obj;
//     IntervalList* range_list;

//     Range_Args() 
//     {  obj = NULL; range_list = NULL; }

//     Range_Args(Optimack* obj_, IntervalList* list)
//     {   obj = obj_; range_list = list;    }
// };

// void Optimack::start_range_recv(IntervalList* list){
//     // if(list->size() != 1){
//     //     printf("start_range_recv: Error - intervallist size != 1");
//     //     list->printIntervals();
//     // }
//     ranges_sent.insertNewInterval_withLock(list->getIntervalList().at(0).start, list->getIntervalList().at(0).end);

//     Range_Args* range_args = new Range_Args(this, list);
//     pthread_t range_thread;
//     if (pthread_create(&range_thread, NULL, range_recv, (void *)range_args) != 0) {
//         ranges_sent.removeInterval_withLock(list->getIntervalList().at(0).start, list->getIntervalList().at(0).end);
//         //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
//         perror("Can't create range_recv thread\n");
//         delete list;
//         list = NULL;
//         delete range_args;
//         range_args = NULL;
//         return;
//     }
// }

// void*
// range_recv(void* arg)
// {
//     int rv, range_sockfd, local_port;
//     char response[MAX_RANGE_SIZE+1];
//     char data[MAX_RANGE_SIZE+1];


//     struct Range_Args* range_args = ((struct Range_Args*)arg);
//     Optimack* obj = range_args->obj;
//     IntervalList* range_job = range_args->range_list;
//     auto range_job_vector = range_job->getIntervalList();
//     local_port = obj->subconn_infos.begin()->second->local_port;

//     unsigned int start_seq = range_job_vector.at(0).start + obj->response_header_len + 1;
//     unsigned int end_seq = range_job_vector.at(0).end + obj->response_header_len + 1;
//     printf("[Range]: range_recv thread starts for [%u, %u]\n", start_seq, end_seq);
//     log_info("[Range]: range_recv thread starts for [%u, %u]", start_seq, end_seq);

//     pthread_mutex_t *mutex = &(obj->mutex_seq_gaps);
//     subconn_info* subconn = (obj->subconn_infos.begin()->second);

//     int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0, packet_len=0;
//     http_header* header = (http_header*)malloc(sizeof(http_header));
//     memset(header, 0, sizeof(http_header));
//     // parser
//     // Http1::RequestParser rp;
//     // SBuf headerBuf;

//     while(!range_job_vector.empty()){

//         if(obj->cur_ack_rel >= end_seq+obj->response_header_len+1){
//             range_job_vector.clear();
//             // printf("[Range]: [%u, %u], cur_ack_rel(%u) >= end_seq(%u), thread ends early before sending\n", start_seq+obj->response_header_len+1, end_seq+obj->response_header_len+1, obj->cur_ack_rel, end_seq+obj->response_header_len+1);
//             log_info("[Range]: [%u, %u], cur_ack_rel(%u) >= end_seq(%u), thread ends early before sending", start_seq+obj->response_header_len+1, end_seq+obj->response_header_len+1, obj->cur_ack_rel, end_seq+obj->response_header_len+1);
//             break;
//         }

//         range_sockfd = obj->establish_tcp_connection();
//         if(range_sockfd <= 0)//TODO: remove ranges_sent?
//             break;
        
//         // obj->ranges_sent.printIntervals();
//         for (auto it = range_job_vector.begin(); it != range_job_vector.end();){
//         // for(auto it : range_job->getIntervalList()) {
//             // printf("[Range] Resend bytes %d - %d\n", it.start, it.end);
//             if(obj->cur_ack_rel < it->end+obj->response_header_len+1){
//                 obj->send_http_range_request(range_sockfd, *it);
//                 it++;
//             }
//             else{
//                 range_job_vector.erase(it);
//                 // it--;
//             }
//             // memset(request+request_len, 0, MAX_RANGE_SIZE-request_len);
//             // sprintf(request+request_len-2, "Range: bytes=%d-%d\r\n\r\n", it.start, it.end);
//             // send(range_sockfd, request, strlen(request), 0);
//             // log_debug("[Range] Resend bytes %d - %d", it.start, it.end);
//         }

//         do {
//             // blocking sock
//             if(recv_offset > MAX_RANGE_SIZE){
//                 printf("recv_offset %d > MAX_RANGE_SIZE %u\n", recv_offset, MAX_RANGE_SIZE);
//                 break;
//             }
//             memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset);
//             rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);
            
//             if(obj->cur_ack_rel >= end_seq+obj->response_header_len+1){
//                 range_job_vector.clear();
//                 // printf("[Range]: [%u, %u], cur_ack_rel(%u) >= end_seq(%u), thread ends early in recv\n", start_seq+obj->response_header_len+1, end_seq+obj->response_header_len+1, obj->cur_ack_rel, end_seq+obj->response_header_len+1);
//                 log_info("[Range]: [%u, %u], cur_ack_rel(%u) >= end_seq(%u), thread ends early in recv", start_seq+obj->response_header_len+1, end_seq+obj->response_header_len+1, obj->cur_ack_rel, end_seq+obj->response_header_len+1);
//                 break;
//             }

//             // printf("[Range]: rv %d\n", rv);
//             if (rv > MAX_RANGE_SIZE)
//                 printf("[Range]: rv %d > MAX %d\n", rv, MAX_RANGE_SIZE);
//             if (rv > 0) {
//                 unread += rv;
//                 consumed = 0;
//                 while (unread > 0) {
//                     if (!header->parsed) {
//                         // parse header
//                         parsed = parse_response(header, response+consumed, unread);
//                         if (parsed <= 0) {
//                             // incomplete http header
//                             // keep receiving and parse in next response
//                             memmove(response, response+consumed, unread);
//                             recv_offset += unread;
//                             printf("[Range]: incomplete http header, len %d\n", unread);
//                             break;
//                         }
//                         else {
//                             // parser
//                             // headerBuf.assign(response+consumed, unread);
//                             // rp.parse(headerBuf);
//                             // printf("[Range]: headBlockSize %d Parsed %d StatusCode %d\n", rp.headerBlockSize(), parsed, rp.parseStatusCode);
//                             // src/http/StatusCode.h

//                             recv_offset = 0;
//                             consumed += parsed;
//                             unread -= parsed;
//                         }
//                     }
//                     else {
//                         // collect data
//                         if (header->remain <= unread) {
//                             // we have all the data
//                             // printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->end, header->remain, unread);
//                             log_debug("[Range] data retrieved %d - %d", header->start, header->end);
//                             // delet completed request
//                             //pthread_mutex_lock(&obj->mutex_range);
//                             // Interval gap(header->start, header->end);
//                             // pthread_mutex_lock(mutex);
//                             // for (auto it = subconn->seq_gaps.begin(); it != subconn->seq_gaps.end(); it++) {
//                                 // if (header->start == (*it).start && header->end + 1 == (*it).end) {
//                                     // subconn->seq_gaps = removeInterval(subconn->seq_gaps, Interval(header->start, header->end+1, ""));
//                                     // break;
//                                 // }
//                             // }
//                             // pthread_mutex_unlock(mutex);
//                             //log_debug("[Range] [Warning] pending request not found");
//                             //pthread_mutex_unlock(&obj->mutex_range);

//                             memcpy(data, response+consumed, header->remain);
//                             header->parsed = 0;
//                             unread -= header->remain;
//                             consumed += header->remain;
//                             unsent = header->end - header->start + 1;
//                             // parser
//                             // rp.clear();
//                             /*
//                             * TODO: send(buf=data, size=unsent) to client here
//                             * remove interval gaps (header->start, header->end) here
//                             */
//                             range_job->removeInterval(header->start, header->end);
//                             // obj->ranges_sent.removeInterval_withLock(header->start, header->end);
//                         }
//                         else {
//                             // still need more data
//                             // we can consume and send all unread data
//                             // printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->start+unread, header->remain, unread);
//                             log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start, header->start+unread, header->remain, unread);
//                             memcpy(data, response+consumed, unread);
//                             header->remain -= unread;
//                             consumed += unread;
//                             unsent = unread;
//                             unread = 0;
//                             /*
//                             * TODO:
//                             * remove interval gaps (header->start, header->start+unread-1) here
//                             */
//                             range_job->removeInterval(header->start, header->start+unsent);
//                             // obj->ranges_sent.removeInterval_withLock(header->start, header->start+unsent);
//                         }

//                         int sent;
//                         for (sent=0; unsent > 0; sent += packet_len, unsent -= packet_len) {
//                             packet_len = unsent >= obj->squid_MSS? obj->squid_MSS : unsent;

//                             // obj->ranges_sent.removeInterval_withLock(header->start+sent, header->start+sent+packet_len);
//                             uint ack = subconn->ini_seq_loc + subconn->next_seq_loc;
//                             uint seq_rel = 1 + obj->response_header_len + header->start + sent;
//                             uint seq = subconn->ini_seq_rem +  seq_rel; // Adding the offset back
//                             send_ACK_payload(obj->g_local_ip, obj->g_remote_ip, local_port, obj->g_remote_port, (u_char*)(data + sent), packet_len, ack, seq);
//                             log_error("range_recv:2132: recved_seq - lock"); 
//                             obj->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+packet_len);
//                             log_error("range_recv:2132: recved_seq - unlock"); 
//                             log_error("range_recv:2132: all_lost_seq - lock"); 
//                             obj->all_lost_seq.insertNewInterval_withLock(seq_rel, seq_rel+packet_len);
//                             log_error("range_recv:2132: all_lost_seq - unlock"); 
//                             log_debug("[Range]: insert [%u,%u] to all_lost_seq", seq_rel, seq_rel+packet_len);
//                             obj->insert_to_recv_buffer(seq_rel, (u_char*)data+sent, packet_len);
//                             log_debug("[Range] retrieved and sent seq %x(%u) ack %x(%u)", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc);
//                             // printf ("[Range] retrieved and sent seq %x(%u) ack %x(%u) len %u\n", ntohl(seq), header->start+obj->response_header_len+sent, ntohl(ack), subconn->next_seq_loc, packet_len);
//                         }
//                         recv_offset = 0;
//                         header->start += sent;
//                     }
//                 }
//                 if (unread < 0)
//                     log_debug("[Range] error: unread < 0");
//             }
//             else if (rv < 0){
//                 if(!(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)){
//                     log_debug("[Range] error: ret %d errno %d", rv, errno);
//                     break;
//                 }
//             }
//             else{ 
//                 log_debug("[Range]: ret %d, sockfd %d closed ", rv, range_sockfd);
//                 break;
//             }
//             usleep(100);
//         } while (!range_job_vector.empty());
//         close(range_sockfd);
//     }
//     free(header);
//     header = NULL;
//     range_job_vector.clear();
//     delete range_job;
//     range_job = NULL;
//     delete range_args;
//     range_args = NULL;

//     log_info("[Range]: [%u, %u] Recved, range_recv thread exits...", start_seq, end_seq);
//     pthread_exit(NULL);
// }


int Optimack::establish_tcp_connection(int old_sockfd)
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
        printf("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(g_remote_ip);
    server_addr.sin_port = htons(g_remote_port);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }
    printf("establish_tcp_connection: connect sockfd %d\n", sockfd);

    if(get_localport(sockfd) < 0){
        sockfd = 0;
        goto opensocket;
    }

    return sockfd;
}

int Optimack::send_http_range_request(int sockfd, Interval range){
    uint start = range.start, end = range.end;
    if (start == end || (start == 0 || end == 0))
        return -1;
    
    char range_request[MAX_RANGE_REQ_LEN];
    memcpy(range_request, request, request_len);
    sprintf(range_request+request_len-2, "Range: bytes=%u-%u\r\n\r\n", start, end);
    if (send(sockfd, range_request, strlen(range_request), 0) < 0){
        // printf("[Range] bytes [%u, %u] failed\n", start, end);
        log_debug("[Range] bytes %d - %d failed", start, end);
        // pthread_join(range_thread, NULL);
        // log_debug("[Range] new range thread created");
        // range_sockfd = init_range(); // Resend the range in range_sent when start a new range watch
        return -1;
    } 
    else{
        requested_bytes += end - start + 1;
        range_request_count++;
        printf("[Range] bytes [%u, %u] requested, No.%d\n", start+response_header_len+1, end+response_header_len+1, range_request_count);
        log_debug("[Range] bytes %d - %d requested, No.%d", start+response_header_len+1, end+response_header_len+1, range_request_count);
        return 0;
    }
}


int Optimack::generate_sack_blocks(unsigned char * buf, int len, IntervalList* seq_list){
    int offset = 0;
    pthread_mutex_lock(seq_list->getMutex());
    auto seq_intvl_list = seq_list->getIntervalList();
    for(int i = 1; i < seq_list->size() && i < 4 && offset+8 <= len; i++){
        *((uint32_t*) (buf + offset)) = htonl(seq_intvl_list.at(i).start);
        *((uint32_t*) (buf + offset + 4)) = htonl(seq_intvl_list.at(i).end);
        log_info("SACK: left %u(%x), right %u(%x)", seq_intvl_list.at(i).start, seq_intvl_list.at(i).start, seq_intvl_list.at(i).end, seq_intvl_list.at(i).end);
        offset += 8;
        // memcpy(buf+offset, &seq_intvl_list.at(i).start, 4);
        // offset += 4;
        // memcpy(buf+offset, &seq_intvl_list.at(i).end, 4);
        // offset += 4;
    }
    pthread_mutex_unlock(seq_list->getMutex());
    return offset;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//extract_sack_blocks(): searches for SACK blocks in data packet (kind = 5, length =X)
//	and writes them to sack array sorted in ascending order. 
//	entry sack[0] is reserved for [old SAN-1, new SAN-1]
//	buf points at beginning of TCP options, 
//	nb_sack provides the number of SACK entries found
//++++++++++++++++++++++++++++++++++++++++++++++++
void Optimack::extract_sack_blocks(unsigned char * const buf, const uint16_t len, IntervalList& sack_list, unsigned int ini_seq) {
	//find sack offset
	int offset = find_offset_of_tcp_option(buf, len, 5);
	if(offset == -1){
		return;
	}

	int sack_len = *(buf + offset + 1);
    // printf("sack_len: %d\n", sack_len);
	offset += 2;
	for (; offset < sack_len; offset += 8)
	{
		unsigned int left = ntohl( *((uint32_t*) (buf + offset)) );
		unsigned int right = ntohl( *((uint32_t*) (buf + offset + 4)) );
        // printf("left: %x, right %x\n", left, right);
		sack_list.insertNewInterval(left - ini_seq, right - ini_seq);
	}
}

void* send_all_requests(void* arg){
    Optimack* obj = (Optimack*)arg;
    // for (size_t i=0; i<obj->subconn_infos.size(); i++) {
    for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++){
        pthread_mutex_lock(&it->second->mutex_opa);
        send_ACK(obj->g_remote_ip, obj->g_local_ip, obj->g_remote_port, it->second->local_port, obj->request, it->second->ini_seq_rem+1, it->second->ini_seq_loc+1);
        it->second->next_seq_loc = 1 + obj->request_len;
        it->second->next_seq_rem = 1;
        pthread_mutex_unlock(&it->second->mutex_opa);
        printf("S%u: Send request %u\n",it->second->id, obj->request_len);
        // if(i < obj->subconn_infos.size()-2)
        // sleep(1);
    }
    bool is_all_request_recved = true;
    while (true){
        sleep(1);//one rtt
        for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++){
            if(it->second->next_seq_rem == 1){
                is_all_request_recved = false;
                send_ACK(obj->g_remote_ip, obj->g_local_ip, obj->g_remote_port, it->second->local_port, obj->request, it->second->ini_seq_rem+1, it->second->ini_seq_loc+1);
                log_info("send_all_requests: S%d timeout, resend request", it->second->local_port);
            }
        }
        if (is_all_request_recved)
            break;
    }
    log_info("send_all_requests: leave...");
    return NULL;
}

int Optimack::process_tcp_packet(struct thread_data* thr_data)
{
    char log[LOGSIZE], time_str[64];

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *tcp_opt = tcp_options(thr_data->buf);
    unsigned int tcp_opt_len = tcphdr->th_off*4 - TCPHDR_SIZE;
    unsigned char *payload = tcp_payload(thr_data->buf);
    unsigned int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);
#ifdef OPENSSL
    if(is_ssl){
        struct TLSHeader *tlshdr = (struct TLSHeader*)payload;
    }
#endif
    // printf("right in process_tcp_packet\n");
    // hex_dump(payload, payload_len);

    // check remote ip, local ip
    // and set key_port
    bool incoming = true;
    char *sip, *dip;
    uint local_port;
    if (g_remote_ip_int == iphdr->saddr) {
        incoming = true;
        sip = g_remote_ip;
        dip = g_local_ip;
        local_port = dport;
    }
    else if (g_remote_ip_int == iphdr->daddr) {
        incoming = false;
        sip = g_local_ip;
        dip = g_remote_ip;
        local_port = sport;
    }

    auto find_ret = subconn_infos.find(local_port);
    if (find_ret == subconn_infos.end()) {
        char sip_[16], dip_[16];
        ip2str(iphdr->saddr, sip_);
        ip2str(iphdr->daddr, dip_);
        sprintf(log, "P%d: ERROR - IP or Subconn not found: %s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", thr_data->pkt_id, sip_, ntohs(tcphdr->th_sport), dip_, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
        printf("%s\n", log);
        return -1;
    }
    subconn_info* subconn = (find_ret->second);
    int subconn_i = subconn->id;

    // Outgoing Packets
    if (!incoming) 
    {   
        switch (tcphdr->th_flags) {
            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
                {
                    // init seq and ack if haven't
                    if (!subconn->seq_init && payload_len) {
                        log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&subconn->mutex_opa);
                        if (!subconn->seq_init && payload_len) {
                            subconn->ini_seq_rem = ack - 1;
                            subconn->next_seq_rem = 1;
                            subconn->ini_seq_loc = seq - 1;
                            subconn->seq_init = true;
                            log_info("Subconn %d seq_init done, seq ini 0x%x(%u)", subconn_i, subconn->ini_seq_rem, subconn->ini_seq_rem);
                            // reply to our send()
                            if (subconn_i) {
                                char empty_payload[] = "";
                                send_ACK(sip, dip, sport, dport, empty_payload, seq+payload_len, ack);
                            }
                        }
                        pthread_mutex_unlock(&subconn->mutex_opa);
                        log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                        // TODO: should we drop if subconn_i==0 ?
                        return -1;
                    }

                    if (subconn_i == 0) {
                        this->rwnd = ntohs(tcphdr->th_win) * win_scale;
                        // this->rwnd = rwnd > 6291456? 6291456 : rwnd;
                        if(rwnd > max_win_size)
                            max_win_size = rwnd;
                        this->cur_ack_rel = ack - subconn->ini_seq_rem;
                        uint cur_ack_rel_local = ack - subconn->ini_seq_rem;
                        this->win_end = cur_ack_rel + rwnd;
                        // log_seq(ack_file, cur_ack_rel_local);

                        // if (is_timeout_and_update(subconn->timer_print_log, 2))
                        // printf("P%d-Squid-out: squid ack %d, win_size %d, max win_size %d\n", thr_data->pkt_id, cur_ack_rel, rwnd, max_win_size);

                        //Todo: cur_ack_rel < 
                        if(BACKUP_MODE){
                            // // pthread_mutex_lock(&subconn_backup->mutex_seq_gaps);
                            // if(subconn_backup->recved_seq.size() > 0) {
                            //     // printf("O-bu: cur_ack_rel %u, seq_gaps[0].end %u\n", cur_ack_rel, subconn_backup->recved_seq.getFirstEnd());
                            //     if(cur_ack_rel <= subconn_backup->recved_seq.getFirstEnd()){
                            //         unsigned char sack_str[33] = {0};
                            //         int len = generate_sack_blocks(sack_str, 32, &recved_seq);
                            //         send_ACK_with_SACK(g_remote_ip, g_local_ip, g_remote_port, subconn_backup->local_port, sack_str, len, "", subconn_backup->ini_seq_rem + cur_ack_rel, subconn_backup->ini_seq_loc + subconn_backup->next_seq_loc, rwnd/subconn_backup->win_scale);
                            //         // if (is_timeout_and_update(timer_print_log, 2))
                            //         // printf("O-bu: sent ack %u when recved squid ack\n", cur_ack_rel);
                            //     }
                            // }
                            // subconn_backup->seq_gaps = insertNewInterval(subconn_backup->seq_gaps, Interval(1, cur_ack_rel, time_in_HH_MM_SS(time_str)));
                            // pthread_mutex_unlock(&subconn_backup->mutex_seq_gaps);
                        }
                        
                        bool is_new_ack = false;
                        int same_ack_cnt_local;
                        pthread_mutex_lock(&mutex_cur_ack_rel);
                        
                        memset(time_str, 0, 64);
                        // pthread_mutex_lock(sack_list.getMutex());
                        if(tcp_opt_len){
                            sack_list.clear();
                            extract_sack_blocks(tcp_opt, tcp_opt_len, sack_list, subconn->ini_seq_rem);
                            // log_info("cur_ack: %u, ini_seq: %u, SACK: ", ack - subconn->ini_seq_rem, subconn->ini_seq_rem);
                            // printf("cur_ack: %u, ini_seq: %u, SACK: ", ack - subconn->ini_seq_rem, subconn->ini_seq_rem);
                            // sack_list.printIntervals();
                            // log_info(recved_seq.Intervals2str().c_str());
                        }
                        // pthread_mutex_unlock(sack_list.getMutex());
                        log_info("P%d-Squid-out: squid ack %u, th_win %u, win_scale %d, win_size %d, max win_size %d, win_end %u, update last_ack_time to %s, SACK: %s\n", thr_data->pkt_id, cur_ack_rel, ntohs(tcphdr->th_win), win_scale, rwnd, max_win_size, cur_ack_rel+rwnd, print_chrono_time(last_ack_time, time_str), sack_list.Intervals2str().c_str());

                        if (cur_ack_rel == last_ack_rel){
                            if(cur_ack_rel < recved_seq.getFirstEnd())
                                same_ack_cnt++;
                            same_ack_cnt_local = same_ack_cnt;
                            if(SLOWDOWN_CONFIG){
                                if(same_ack_cnt >= 4){
                                    bool can_slow_down = false;
                                    unsigned int interval = 100, dup = 100;
                                    if (cur_ack_rel - last_slowdown_ack_rel > subconn_infos.begin()->second->payload_len*interval){
                                        same_ack_cnt = 0;
                                        can_slow_down = true;
                                        printf("P%d-Squid-out: can slow down, new ack with interval %d\n", thr_data->pkt_id, interval);
                                    }
                                    else if( last_slowdown_ack_rel == cur_ack_rel && same_ack_cnt % dup == 0){
                                        can_slow_down = true;
                                        printf("P%d-Squid-out: can slow down, dup ack %d\n", thr_data->pkt_id, same_ack_cnt);
                                    }

                                    if(can_slow_down){
                                        // for (size_t i=1; i<subconn_infos.size(); i++)
                                        for (auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++)
                                            adjust_optimack_speed(it->second, it->second->id, -1, 100);
                                        last_slowdown_ack_rel = cur_ack_rel;
                                    }
                                }
                            }
                        }
                        else{
                            // printf("P%d-Squid-out: squid ack %d, seq_global %d, win_size %d, max win_size %d\n", thr_data->pkt_id, cur_ack_rel, seq_next_global, rwnd, max_win_size);
                            
                            // log_debugv("P%d-S%d-out: process_tcp_packet:737: mutex_seq_gaps - trying lock", thr_data->pkt_id, subconn_i);                            
                            // pthread_mutex_lock(&mutex_seq_gaps);
                            // if(!seq_gaps.empty()){
                            //     // printf("P%d-Squid-out: trying to remove 1-%u\nBefore removing:\n", thr_data->pkt_id, cur_ack_rel);
                            //     seq_gaps = removeInterval(seq_gaps, Interval(1, cur_ack_rel)); //packet received from subconn 0
                            //     if (!seq_gaps.empty() && seq_gaps.at(0).start < cur_ack_rel) {
                            //         log_error("P%d-Squid-out: Not removing correctly", thr_data->pkt_id);
                            //         printIntervals(seq_gaps);
                            //     }
                            // }
                            // pthread_mutex_unlock(&mutex_seq_gaps);
                            // log_debugv("P%d-S%d-out: process_tcp_packet:737: mutex_seq_gaps - unlock", thr_data->pkt_id, subconn_i); 
                            last_ack_time = std::chrono::system_clock::now();
                            last_ack_epochtime = get_current_epoch_time_second();
                            if(cur_ack_rel-last_ack_rel > 10*squid_MSS)
                                resend_cnt = 0;
                            same_ack_cnt = 0;
                            same_ack_cnt_local = 0;
                            is_new_ack = true;
                            last_ack_rel = cur_ack_rel;
                            // remove_recved_recv_buffer(cur_ack_rel);
                        }
                        pthread_mutex_unlock(&mutex_cur_ack_rel);
                        log_debugv("P%d-S%d-out: process_tcp_packet:710: mutex_cur_ack_rel - unlock", thr_data->pkt_id, subconn_i); 

                        // if(BACKUP_MODE && is_new_ack){
                        //     subconn_infos[backup_port]->recved_seq.insertNewInterval_withLock(1, cur_ack_rel);
                        //     log_info("[Backup]: recved ack from squid, insert [1, %u], then %s\n", cur_ack_rel, subconn_infos[backup_port]->recved_seq.Intervals2str().c_str());
                        // }
                        //     pthread_mutex_lock(&mutex_recv_buffer);
                        //     remove_recved_recv_buffer(cur_ack_rel_local);
                        //     // if(recved_seq.getFirstEnd()-cur_ack_rel_local > 100*squid_MSS){
                        //     //     send_out_of_order_recv_buffer(cur_ack_rel_local);
                        //     // }
                        //     pthread_mutex_unlock(&mutex_recv_buffer);
                        // }
                        // else if(same_ack_cnt_local == 10){
                        //     log_info("same ack cnt == 5, resend recv_buffer");
                        //     send_out_of_order_recv_buffer_withLock(cur_ack_rel_local);
                        // }
                        // if(elapsed(last_ack_time) > 2){
                        //     log_info("last_ack_time > 2, resend recv_buffer");
                        //     send_out_of_order_recv_buffer_withLock(cur_ack_rel_local);                            
                        // }
                        // if (elapsed(last_rwnd_write_time) >= 1){
                        //     fprintf(rwnd_file, "%s, %u\n", cur_time.time_in_HH_MM_SS_US(), ntohs(tcphdr->th_win)*2048);
                        //     last_rwnd_write_time = std::chrono::system_clock::now();
                        // }                       

                        if (!payload_len) {      

                            if (subconn_infos.begin()->second->payload_len && seq_next_global > cur_ack_rel) { ////packet received from subconn 0
                                float off_packet_num = (seq_next_global-cur_ack_rel)/subconn_infos.begin()->second->payload_len;
                                subconn_infos.begin()->second->off_pkt_num = off_packet_num;

                                // if (last_ack_rel != cur_ack_rel) {
                                if (last_off_packet != off_packet_num) {
                                    // log_debug("P%d-Squid-out: squid ack %d, seq_global %d, off %.2f packets, win_size %d, max win_size %d", thr_data->pkt_id, cur_ack_rel, seq_next_global, off_packet_num, rwnd, max_win_size);
                                    // fprintf(log_file, "%s, %.2f\n", cur_time.time_in_HH_MM_SS_US(), off_packet_num);
                                    last_off_packet = off_packet_num;
                                }

                                // if (off_packet_num > 0.9*rwnd/subconn_infos.begin()->payload_len){
                                //     log_debug("P%d-Squid-out: > 0.9*rwnd",  thr_data->pkt_id);
                                //     does_packet_lost_on_all_conns();
                                // }
                                // // Packet lost on all connections
                                // bool is_all_lost = true;
                                // for(size_t i = 1; i < subconn_infos.size(); i++){
                                //     // printf("next_seq_rem %u, cur_ack_rel %u, payload_len %u\n", subconn_infos[i].next_seq_rem, cur_ack_rel, subconn_infos.begin()->payload_len);
                                //     if (subconn_infos[i].next_seq_rem < cur_ack_rel + subconn_infos.begin()->payload_len * 10000){
                                //         is_all_lost = false;
                                //     }
                                // }
                                // if (is_all_lost){
                                //     printf("\n\n###################\nPacket lost on all connections. \n###################\n\nlast ack:%d\n", cur_ack_rel);
                                //     for(size_t i = 1; i < subconn_infos.size(); i++){
                                //         printf("S%d: %d\n", i, subconn_infos[i].next_seq_rem);
                                //     }

                                //     exit(-1);
                                // }
                            }
                        

                            //if(off_packet_num < 0.01 && ack_rel > last_speedup_ack_rel+500000 && ack_rel > 5000000){
                            //pthread_mutex_lock(&mutex_subconn_infos);
                            //if (ack_rel > 4*last_speedup_ack_rel){
                            //last_speedup_ack_rel = ack_rel;
                            //printf("P%d-Squid-out: ack pacing speed up by 100!\n", thr_data->pkt_id);
                            //for (size_t i = 0; i < subconn_infos.size(); ++i)
                            //{
                            //if(subconn_infos[i].ack_pacing > 100)
                            //subconn_infos[i].ack_pacing -= 100;
                            //}
                            //}
                            //pthread_mutex_unlock(&mutex_subconn_infos);
                            //}
                            return -1;
                        }
#ifdef OPENSSL
                        if(tlshdr->type == TLS_TYPE_HANDSHAKE || tlshdr->type == TLS_TYPE_CHANGE_CIPHER_SPEC)
                            return 0;
#endif
                        // if payload_len != 0, assume it's request
                        // squid connection with payload -> copy request, our connection -> only update seq/ack 
                        if(request_recved)
                            return -1;

                        memset(request, 0, 1000);
                        memcpy(request, payload, payload_len);
                        request_len = payload_len;
                        request_recved = true;
                        log_info("P%d-Squid-out: request sent to server %d", thr_data->pkt_id, payload_len);
                        // check if we can send request now
                        log_info("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&mutex_subconn_infos);
                        
                        // for (size_t i=1; i<subconn_infos.size(); i++)
                        for (auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++)
                            if (it->second->seq_init == false) {
                                pthread_mutex_unlock(&mutex_subconn_infos);
                                log_debugv("P%d-S%d-out: process_tcp_packet: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                                return -1;
                            }
                        // all done, start to send request
                        pthread_t request_thread;
                        if (pthread_create(&request_thread, NULL, send_all_requests, (void*)this) != 0) {
                                log_error("Fail to create send_all_requests thread.");
                        }
                        log_info("P%d-Squid-out: sent request to all connections", thr_data->pkt_id);
                        seq_next_global = 1;
                        pthread_mutex_unlock(&mutex_subconn_infos);
                        log_info("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                    }
                    else{
                            log_info("P%d-S%d-out: ack %u, win %d", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_rem, ntohs(tcphdr->th_win) * subconn->win_scale);
                    }
                    return -1;
                    break;
                }
            
            default://Could be FIN
                log_debug("[default drop] P%d-S%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d", thr_data->pkt_id, subconn_i, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq-subconn->ini_seq_rem, tcphdr->th_ack, ack-subconn->ini_seq_loc, iphdr->ttl, payload_len);
                return -1;
        }
    }
    // Incoming Packets
    else        
    {
        
        //debugs(1, DBG_CRITICAL, log);
        unsigned int seq_rel = seq - subconn->ini_seq_rem;

        sprintf(log, "P%d-S%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d", thr_data->pkt_id, subconn_i, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq-subconn->ini_seq_rem, tcphdr->th_ack, ack-subconn->ini_seq_loc, iphdr->ttl, payload_len);
        // log_info(log);

        switch (tcphdr->th_flags) {
            /*
            * 1. 在httpAccept里加只有remote_ip, remote_port的iptablesguize
            * 2. 这里抓到squid发给server的SYN包，加squid连接的subconn_info, 复制test.c 1068-1077, 1087, SYN 发出去
            * 3. 收到server的SYN/ACK，判断是squid还是我们的连接，如果是squid，放走accept,如果是我们的，回ack（473-476）,判断是否所有连接都发了ack(479-486)，是否收到request(自己写)，向所有连接发请求(487-492)
            * 4. 抓到squid发给server的ACK包,都放行(accept),如果有长度，就是request，把payload复制下来
            */
            // case TH_SYN:
            // {
                // return process_incoming_SYN();
            //     break;
            // }
            //case TH_SYN | TH_ACK:
            //{
                // return process_incoming_SYNACK();
                //break;
            //}
            case TH_ACK | TH_FIN:
            case TH_ACK | TH_FIN | TH_PUSH:
            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
            {
                if((!payload_len || payload_len == 1) && seq_rel != 1){
                    // Keep alive
                    if(!subconn->is_backup){
                        int adjust_rwnd_tmp = get_ajusted_rwnd(seq_rel+1);
                        if(adjust_rwnd_tmp <= squid_MSS)
                            adjust_rwnd_tmp = squid_MSS;
                        send_optimistic_ack(subconn, seq_rel, adjust_rwnd_tmp+1); // Reply to Keep-Alive
                        send_optimistic_ack(subconn, seq_rel+1, adjust_rwnd_tmp); // Reply to Keep-Alive
                        printf("S%d: received Keep-Alive(%u), len %d, send Keep-Alive ACK with win_size %d\n", subconn_i, seq_rel, payload_len, adjust_rwnd_tmp);
                        if(seq_rel+1 < max_opt_ack)
                            max_opt_ack = seq_rel + 1;
                    }
                    else{
                        // if(seq_rel+payload_len <= max_opt_ack){
                            // send_optimistic_ack(subconn, seq_rel+payload_len, get_ajusted_rwnd(seq_rel+payload_len)); // Reply to Keep-Alive
                            // if(seq_rel+payload_len+1 <= max_opt_ack)
                                // send_optimistic_ack(subconn, seq_rel+payload_len+1, get_ajusted_rwnd(seq_rel+payload_len+1)); // Reply to Keep-Alive
                        // }
                    }
                }

                if (!payload_len) {
                    recved_seq.insertNewInterval_withLock(seq_rel, seq_rel);
                    update_subconn_next_seq_rem(subconn, seq_rel+payload_len);
                    // TODO: let our reply through...for now
                    if (subconn_i)
                        return 0;

                    log_info("P%d-S%d-in: server or our ack %u", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_loc);
                    return -1;
                }


                // if(!subconn->payload_len && subconn->optim_ack_stop){
                if(BACKUP_MODE){
                    if(subconn->is_backup && subconn->optim_ack_stop){
                        pthread_mutex_lock(&subconn->mutex_opa);
                        if(subconn->is_backup && subconn->optim_ack_stop){
                            //Start backup listening thread
                        start_optim_ack_backup(local_port, subconn->ini_seq_rem + 1, subconn->next_seq_loc+subconn->ini_seq_loc, payload_len, 0); //TODO: read MTU
                        printf("S%d: Backup connection, not optim ack\n", subconn_i);
                        pthread_mutex_unlock(&subconn->mutex_opa);
                        }
                    }
                }

                if(RANGE_MODE){
                    if(seq_rel > 1 && range_stop){
                        pthread_mutex_lock(&mutex_range);
                        if(seq_rel > 1 && range_stop){
                            range_stop = 0;
                            if (pthread_create(&range_thread, NULL, range_watch, (void*)this) != 0) {
                                log_error("Fail to create range_watch thread.");
                            }
                        }
                        pthread_mutex_unlock(&mutex_range);

                    }
                }

                if(seq_rel >= 1 && optim_ack_stop){
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                    pthread_mutex_lock(&mutex_subconn_infos);
                    if(optim_ack_stop){
                        std::map<uint, struct subconn_info*>::iterator it;
                        for (it = ++subconn_infos.begin(); it != subconn_infos.end(); it++)
                            if (!it->second->is_backup && it->second->next_seq_rem <= 1) {
                                send_optimistic_ack(it->second, 1, get_ajusted_rwnd(1));
                                break;
                            }
                        if (it == subconn_infos.end() && recved_seq.getFirstEnd() > 1){
                        // if(recved_seq.getFirstEnd() > 1){
                            // if(optim_ack_stop){
                                start_optim_ack_altogether(subconn->ini_seq_rem + 1, subconn->next_seq_loc+subconn->ini_seq_loc, payload_len, 0); //TODO: read MTU
                                printf("P%d-S%d: Start optimistic_ack_altogether\n", thr_data->pkt_id, subconn_i);
                            // }
                        }
                    }
                    pthread_mutex_unlock(&mutex_subconn_infos);
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                }

                if(overrun_stop == -1) {
                    // log_info("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                    pthread_mutex_lock(&mutex_subconn_infos);
                    std::map<uint, struct subconn_info*>::iterator it;
                    for (it = ++subconn_infos.begin(); it != subconn_infos.end(); it++)
                        if (subconn->optim_ack_stop == 1) {
                            break;
                        }
                    if (it == subconn_infos.end()){
                        if(overrun_stop == -1){
                            overrun_stop++;
                            if (pthread_create(&overrun_thread, NULL, overrun_detector, (void*)this) != 0) {
                                log_error("Fail to create overrun_detector thread.");
                            }
                        }
                    }
                    pthread_mutex_unlock(&mutex_subconn_infos);
                    // log_info("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                }

                if(seq_rel == 1){
                    Http1::ResponseParser rp;
                    SBuf headerBuf;
                    headerBuf.assign((char*)payload, payload_len);
                    rp.parse(headerBuf);
                    response_header_len = rp.messageHeaderSize();
                    // response_header_len = 398;
                    memcpy(response, payload, response_header_len);

                    const char* content_len_field = "Content-Length: ";
                    int content_len_field_len = strlen(content_len_field);
                    char* p_content_len = std::search((char*)payload, (char*)payload+payload_len, content_len_field, content_len_field+content_len_field_len);
                    p_content_len += content_len_field_len;
                    file_size = (u_int)strtol(p_content_len, &p_content_len, 10);
                    ack_end = file_size + response_header_len+1;
                    printf("S%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn_i, response_header_len, rp.parseStatusCode, file_size, ack_end);
                    log_info("S%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn_i, response_header_len, rp.parseStatusCode, file_size, ack_end);
                    // printf("seq in this conn-%u, file byte-%u, %c\n", seq_rel+response_header_len, 0, payload[response_header_len+1]);
                    // src/http/StatusCode.h
                }

                // if(!subconn_i){
                //     fprintf(seq_file, "%s, %u\n", time_in_HH_MM_SS_US(time_str), seq_rel);
                // }

                // log_seq(recv_seq_file, local_port, seq_rel);

                // pthread_mutex_lock(&mutex_seq_next_global);
                int order_flag;
                bool is_new_segment = false;
                IntervalList temp_range;
                temp_range.clear();
                temp_range.insertNewInterval(seq_rel, seq_rel+payload_len);
                pthread_mutex_lock(recved_seq.getMutex());
                temp_range.substract(&recved_seq);
                auto temp_range_list = temp_range.getIntervalList();
                if(temp_range.size()){
                    for(auto it = temp_range_list.rbegin(); it != temp_range_list.rend(); it++){
                    // for(auto& intvl: temp_range.getIntervalList()){
                        is_new_segment = recved_seq.checkAndinsertNewInterval(it->start, it->end, order_flag);
                        seq_next_global = recved_seq.getLastEnd();
                        // is_new_segment = recved_seq.checkAndinsertNewInterval(intvl.start, intvl.end, order_flag);
                        if(is_new_segment){//change to Interval
                            unsigned char* intvl_data = payload+it->start-seq_rel;
                            int intvl_data_len = it->end-it->start;
                            if(order_flag == IN_ORDER_NEWEST){
                                subconn->last_inorder_data_time = std::chrono::system_clock::now();
                                send_data_to_squid(it->start, intvl_data, intvl_data_len);
                                sprintf(log,"%s inorder newest, forwarded to squid, ", log); 
                            }
                            else if(order_flag == IN_ORDER_FILL){
                                subconn->last_inorder_data_time = std::chrono::system_clock::now();
                                log_info("process_tcp_packet: resend in order fill, seq %u", it->start);
                                send_data_to_squid(it->start, intvl_data, intvl_data_len);
                                send_out_of_order_recv_buffer_withLock(it->end);
                                sprintf(log,"%s - inorder fill, sent to squid,", log); 
                            }
                            else{
                                insert_to_recv_buffer_withLock(it->start, intvl_data, intvl_data_len);
                                sprintf(log,"%s - out of orders, don't sent, ", log); 
                            }
                        }
                        else
                            printf("Error! process incoming packet: is_new_segment is false!!!\n");
                    }
                    // if(recved_seq.getFirstEnd()-cur_ack_rel > 20*squid_MSS)
                    //     send_out_of_order_recv_buffer(cur_ack_rel, recved_seq.getFirstEnd());
                }
                pthread_mutex_unlock(recved_seq.getMutex());

                update_subconn_next_seq_rem(subconn, seq_rel+payload_len);

                if(recved_seq.getFirstEnd() == 1){
                    send_optimistic_ack(subconn, 1, get_ajusted_rwnd(1));
                }

                // sprintf(log, "%s - %s", log, recved_seq.Intervals2str().c_str());
                // log_info(recved_seq.Intervals2str().c_str());
                // if (!is_new_segment && recved_seq.getLastEnd() != seq_next_global){
                //     printf("not new segment but seq_next_global changed from %u to %u\n", seq_next_global, recved_seq.getLastEnd());
                //     log_info("not new segment but seq_next_global changed from %u to %u\n", seq_next_global, recved_seq.getLastEnd());
                //     sleep(5);
                //     exit(-1);
                // }
                // bytes_per_second[time_in_HH_MM_SS(time_str)] += seq_rel + payload_len - subconn->next_seq_rem;
                // sprintf(log, "%s - cur seq_next_global %u", log, seq_next_global);
                // if (seq_next_global < seq_rel + payload_len)
                //     seq_next_global = seq_rel + payload_len;
                // sprintf(log,"%s - update seq_next_global to %u", log, seq_next_global);
                // pthread_mutex_unlock(&mutex_seq_next_global);


                // pthread_mutex_lock(subconn->recved_seq.getMutex());

                // sprintf(log, "%s - cur next_seq_rem %u", log, subconn->next_seq_rem);
                // if (subconn->next_seq_rem <= seq_rel + payload_len) {//overlap: seq_next_global:100, seq_rel:95, payload_len = 10
                //     subconn->next_seq_rem = seq_rel + payload_len;
                // }
                // memset(time_str, 0, 64);
                // sprintf(log,"%s - update next_seq_rem to %u - update last_data_received %s", log, subconn->next_seq_rem, print_chrono_time(subconn->last_data_received, time_str));
                // pthread_mutex_unlock(&subconn->mutex_opa);

                    // printf("%s - insert interval[%u, %u]\n", time_str, subconn->next_seq_rem, seq_rel);
                    // log_debug(Intervals2str(subconn->seq_gaps).c_str());
                    // log_info("%d, [%u, %u]", subconn_i, subconn->next_seq_rem, seq_rel);
                    // sprintf(log,"%s - insert interval[%u, %u]", log, subconn->next_seq_rem, seq_rel);

                if (BACKUP_MODE && subconn->is_backup){
                    //Normal Mode
                    int order_flag_backup;
                    bool is_new_segment_backup = subconn->recved_seq.checkAndinsertNewInterval_withLock(seq_rel, seq_rel+payload_len, order_flag_backup);
                    log_info("[Backup]: insert [%u, %u], after %s\n", seq_rel, seq_rel+payload_len, subconn->recved_seq.Intervals2str().c_str());
                    
                    char empty_payload[] = "";
                    pthread_mutex_lock(&subconn->mutex_opa);
                    uint inorder_seq_end = subconn->recved_seq.getFirstEnd();// subconn->seq_gaps[0].end;
                    // if (inorder_seq_end > cur_ack_rel)
                    //     inorder_seq_end = cur_ack_rel;
                    if (inorder_seq_end > seq_rel+payload_len)
                        inorder_seq_end = seq_rel+payload_len;
                    if(seq_rel == 1 && payload_len != subconn->payload_len){
                        send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + 1 + payload_len, ack, rwnd/subconn->win_scale);
                        sprintf(log, "%s - Sent ack %u", log, 1 + payload_len);
                    }
                    else {
                        if(seq_rel+payload_len <= cur_ack_rel){
                            backup_dup_ack = seq_rel+payload_len;
                            int adjusted_rwnd = get_ajusted_rwnd_backup(backup_dup_ack);
                            if(adjusted_rwnd > 0){
                                backup_dup_ack_rwnd =  adjusted_rwnd;
                                // backup_dup_ack_rwnd = get_ajusted_rwnd(inorder_seq_end);
                                send_optimistic_ack_with_SACK(subconn, backup_dup_ack, backup_dup_ack_rwnd, &subconn->recved_seq);
                                log_info("[Backup]: send optim ack %u when recved data %u, win %u\n", inorder_seq_end, seq_rel, backup_dup_ack_rwnd);
                                if(backup_dup_ack > this->backup_max_opt_ack)
                                    this->backup_max_opt_ack = backup_dup_ack;
                            }
                        }
                        else if(order_flag_backup == IN_ORDER_NEWEST || order_flag_backup == IN_ORDER_FILL){
                            backup_dup_ack = inorder_seq_end;
                            int adjusted_rwnd = get_ajusted_rwnd_backup(inorder_seq_end);
                            if(adjusted_rwnd > 0){
                                backup_dup_ack_rwnd =  adjusted_rwnd;
                                // backup_dup_ack_rwnd = get_ajusted_rwnd(inorder_seq_end);
                                send_optimistic_ack_with_SACK(subconn, inorder_seq_end, backup_dup_ack_rwnd, &subconn->recved_seq);
                                log_info("[Backup]: send normal ack %u when recved data %u, win %u\n", inorder_seq_end, seq_rel, backup_dup_ack_rwnd);
                                if(backup_dup_ack > this->backup_max_opt_ack)
                                    this->backup_max_opt_ack = backup_dup_ack;
                            }
                            if(order_flag_backup == IN_ORDER_FILL){
                                uint send_end = subconn->recved_seq.getFirstEnd();
                                if(send_end < cur_ack_rel)
                                    send_end = cur_ack_rel;
                                for(uint m = backup_dup_ack; m <= send_end; m += squid_MSS)
                                    send_optimistic_ack_with_SACK(subconn, m, get_ajusted_rwnd_backup(m), &subconn->recved_seq);
                            }
                        }
                        else {
                            // send_optimistic_ack_with_SACK(subconn, inorder_seq_end, backup_dup_ack_rwnd, &subconn->recved_seq);
                        }
                        // if(get_min_next_seq_rem() > cur_ack_rel){ //&& inorder_seq_end < cur_ack_rel
                        //     for (int j = 0; j < 2; j++){
                        //         send_optimistic_ack_with_SACK(subconn, inorder_seq_end, rwnd, &subconn->recved_seq);
                        //         // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + inorder_seq_end, ack, cur_win_scale);
                        //         printf("O-bu: retrx - Sent ack %u\n", inorder_seq_end);
                        //         log_info("O-bu: retrx - Sent ack %u\n", inorder_seq_end);
                        //     }
                        // }

                    }

                    // int cur_win_scale = (cur_ack_rel + rwnd - inorder_seq_end + subconn->ini_seq_rem) / win_scale;
                    // if (cur_win_scale > 0) {

                        // for(uint start = seq_rel+payload_len; start < inorder_seq_end; start += subconn->payload_len){
                        //     send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + start, ack, cur_win_scale);
                        //     // printf("Sent ack %u\n", start);
                        // }
                        // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + inorder_seq_end, ack, cur_win_scale);
                        // sprintf(log, "%s - Sent ack %u", log, inorder_seq_end);

                        // if(seq_rel+payload_len < inorder_seq_end && subconn->recved_seq.getIntervalList().size() > 1){ //trigger next retrx
                        //     for (int j = 0; j < 2; j++){
                        //         send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + inorder_seq_end, ack, cur_win_scale);
                        //         printf("O-bu: retrx - Sent ack %u\n", inorder_seq_end);
                        //     }
                        // }
                    // }
                    pthread_mutex_unlock(&subconn->mutex_opa);
                }

                if(payload_len != squid_MSS){
                    sprintf(log, "%s -unusual payload_len!%d-%d,", log, payload_len, subconn_infos[squid_port]->payload_len);
                    // printf("%s - unusual payload_len!%d-%d,", log, payload_len, subconn_infos[squid_port]->payload_len);
                    // if(elapsed(subconn->last_data_received) > 1.5 && seq_rel+payload_len == subconn->next_seq_rem && seq_rel+payload_len == get_min_next_seq_rem()){
                    if(seq_rel+payload_len <= max_opt_ack ){
                        sprintf(log, "%s - opt_ack(%u) has passed this point, send ack to unusal len %u", log, max_opt_ack, seq_rel+payload_len);
                        // printf("%s - opt_ack(%u) has passed this point, send ack to unusal len %u", log, max_opt_ack, seq_rel+payload_len);
                        int rwnd_tmp = get_ajusted_rwnd(seq_rel+payload_len);
                        if(rwnd_tmp > 0)
                            send_optimistic_ack(subconn, seq_rel+payload_len, rwnd_tmp);
                    // send_ACK_adjusted_rwnd(subconn, seq_rel + payload_len);
                    // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + seq_rel + payload_len, ack, (cur_ack_rel + rwnd/2 - seq_rel - payload_len)/subconn->win_scale);
                    }
                    else{
                        sprintf(log, "%s - not window full, elapsed(subconn->last_data_received) = %f < 1.5 || seq_rel+payload_len(%u) != subconn->next_seq_rem(%u) || seq_rel+payload_len(%u) != get_min_next_seq_rem(%u)", log, elapsed(subconn->last_data_received), seq_rel+payload_len, subconn->next_seq_rem, seq_rel+payload_len, get_min_next_seq_rem());
                    }
                }

                if(TH_FIN & tcphdr->th_flags){
                    printf("S%d: Received FIN/ACK. Sent FIN/ACK. %u\n", subconn_i, seq_rel);
                    log_info("S%d: Received FIN/ACK. Sent FIN/ACK.", subconn_i);
                    // send_FIN_ACK(g_local_ip, g_remote_ip, subconn->local_port, g_remote_port, "", seq+1, ack+1);
                    subconn->fin_or_rst_recved = true;
                }

                // Too many packets forwarded to squid will cause squid to discard right most packets
                if(!is_new_segment && !subconn->is_backup){
                // if (seq_rel + payload_len <= cur_ack_rel) {
                    // printf("P%d-S%d: discarded\n", thr_data->pkt_id, subconn_i); 
                    log_debug("%s - discarded\n", log);
                    return -1;
                }

                // if (seq_rel >= cur_ack_rel + rwnd){
                    // sprintf(log, "%s - Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u", log, seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    // log_info("Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u", seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    // printf("Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u\n", seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    // sleep(1);
                // }
                // // send to squid 
                // // 1. dest port -> sub1->localport
                // // 2. seq -> sub1->init_seq_rem + seq_rel
                // // 3. ack -> sub1->next_seq_loc
                // // 4. checksum(IP,TCP)
                // if (is_timeout_and_update(subconn->timer_print_log, 2))
                //     printf("%s - forwarded to squid\n", log);
#ifdef OPENSSL
                //find IV
                // unsigned char iv[13];
                // snprintf(iv, 12, "%s%s", subconn->salt, explicit_nouce);
                // iv[12] = 0;
                //decrypt packet
                // unsigned char plaintext[2000];
                // gcm_decrypt(payload+8, payload_len-8, subconn->session_key, iv, 12, plaintext);
                //encrypt packet
#endif
                // log_seq(recv_seq_file, seq_rel);
                // // if(rand() % 100 < 1)
                // //     return -1;
                // if(order_flag == OUT_OF_ORDER){
                //     log_debug("%s - out-of-order, discard\n", log); 
                //     return -1;
                // }
                // else {
                //     // if (seq_rel > win_end){
                //     //     log_debug("%s - seq_rel(%u) > win_end(%u), discard\n", log, seq_rel, win_end); 
                //     //     return -1;
                //     // }
                //     // last_inorder_data_epochtime = get_current_epoch_time();
                //     if(order_flag == IN_ORDER_FILL){
                //         log_debug("%s - inorder fill, sent to squid\n", log); 
                //         // send_out_of_order_recv_buffer_withLock(temp_range_list.at(0).start);
                //         return -1;
                //     }
                //     // log_seq(forward_seq_file, seq_rel);
                //     modify_to_main_conn_packet(subconn, tcphdr, thr_data->buf, thr_data->len, seq_rel);
                //     log_debug("%s inorder newest, forwarded to squid\n", log); 
                //     return 0;
                // }
                // log_debug("%s - forwarded to squid\n", log); 
                // return 0;
                strcat(log,"\n");
                log_info(log);
                return -1;
                break;
            }
            // case TH_ACK | TH_FIN:
            // case TH_ACK | TH_FIN | TH_PUSH:
            // {
            //     printf("S%d: Received FIN/ACK. Sent FIN/ACK. %u\n", subconn_i, seq-subconn->ini_seq_rem);
            //     log_info("S%d: Received FIN/ACK. Sent FIN/ACK.", subconn_i);
            //     // send_FIN_ACK(g_local_ip, g_remote_ip, subconn->local_port, g_remote_port, "", seq+1, ack+1);
            //     subconn->fin_ack_recved = true;

                // log_debugv("P%d-S%d: process_tcp_packet:1386: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                // pthread_mutex_lock(&mutex_subconn_infos);    
                // if(!subconn->optim_ack_stop){
                //     subconn->optim_ack_stop++;
                //     // pthread_join(subconn->thread, NULL);
                //     close(subconn->sockfd);
                // }

                // if(!overrun_stop){    
                //     std::map<uint, struct subconn_info*>::iterator it;

                //     // for (i = 0; i < subconn_infos.size(); i++)
                //     for (it = subconn_infos.begin(); it != subconn_infos.end(); it++)
                //         if (!it->second->fin_ack_recved) {
                //             break;
                //         }
                //     if (it == subconn_infos.end()){
                //         printf("All subconns received FIN/ACK!\n");
                //         // close(main_fd);
                //         // send_RST(g_remote_ip, g_local_ip, g_remote_port, subconn_infos.begin()->second->local_port, "", subconn_infos.begin()->second->ini_seq_rem+cur_ack_rel);
                //         // printf("RST sent\n");
                        
                //         // if(!overrun_stop){
                //         //     printf("stop overrun thread\n");
                //         //     overrun_stop++;
                //         // //     pthread_join(overrun_thread, NULL);  
                //         // }
                //         //TODO: close nfq_thread
                //         // TODO: cleanup iptables or cleanup per subconn                               
                //     }
                // }
                // pthread_mutex_unlock(&mutex_subconn_infos);                               
                // log_debugv("P%d-S%d: process_tcp_packet:1386: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 

            //     if(payload_len){
            //         log_debug("%s - sent to squid\n", log); 
            //         tcphdr->th_flags = TH_ACK | TH_PUSH;
            //         modify_to_main_conn_packet(subconn, tcphdr, thr_data->buf, thr_data->len, seq-subconn->ini_seq_rem);
            //         compute_checksums(thr_data->buf, 20, thr_data->len);
            //         return 0;
            //     }
            //     return -1;
            //     break;
            // }
            case TH_RST:
            case TH_RST | TH_ACK:
            {
                if(!subconn->fin_or_rst_recved){
                    printf("S%d: Received RST. Do nothing.\n",subconn_i);
                    subconn->fin_or_rst_recved = true;
                }
                // printf("S%d: Received RST. Make it backup.\n",subconn_i);
                // subconn->is_backup = true;
                // printf("S%d: Received RST. Close this connection.\n",subconn_i);
                // close(subconn->sockfd);
                // pthread_mutex_lock(&mutex_subconn_infos);
                // subconn_infos.erase(find_ret);
                // pthread_mutex_unlock(&mutex_subconn_infos);

            }
            default:
                // printf("P%d-S%d: Invalid tcp flags: %s\n", thr_data->pkt_id, subconn_i, tcp_flags_str(tcphdr->th_flags));
                break;
        }
        return -1;
    }
}

void Optimack::update_subconn_next_seq_rem(struct subconn_info* subconn, uint num){
    pthread_mutex_lock(&subconn->mutex_opa);
    if (subconn->next_seq_rem < num) {//overlap: seq_next_global:100, seq_rel:95, payload_len = 10
        subconn->next_seq_rem = num;
        subconn->last_data_received = std::chrono::system_clock::now();
        // log_seq(processed_seq_file, local_port, seq_rel);
    }
    // if(BACKUP_MODE && subconn->is_backup)
        // subconn->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+payload_len);
    // subconn->next_seq_rem = subconn->recved_seq.getLastEnd();
    pthread_mutex_unlock(&subconn->mutex_opa);
}

int Optimack::modify_to_main_conn_packet(struct subconn_info* subconn, struct mytcphdr* tcphdr, unsigned char* packet, unsigned int packet_len, unsigned int seq_rel){
    if(subconn->local_port == squid_port)//Main subconn, return directly
        return 0; 

    tcphdr->th_dport = htons(subconn_infos.begin()->second->local_port);
    tcphdr->th_seq = htonl(subconn_infos.begin()->second->ini_seq_rem + seq_rel);
    tcphdr->th_ack = htonl(subconn_infos.begin()->second->ini_seq_loc + subconn_infos.begin()->second->next_seq_loc);
    compute_checksums(packet, 20, packet_len);
    // send_ACK_payload(g_local_ip, g_remote_ip,subconn_infos.begin()->local_port, g_remote_port, payload, payload_len,subconn_infos.begin()->ini_seq_loc + subconn_infos.begin()->next_seq_loc, subconn_infos.begin()->ini_seq_rem + seq_rel);
    // printf("P%d-S%d: forwarded to squid\n", thr_data->pkt_id, subconn_i); 
    // if(rand() % 100 < 50)
        return 0;
}

int Optimack::get_localport(int fd){
    // Get my port
    struct sockaddr_in my_addr;
    socklen_t len = sizeof(my_addr);
    bzero(&my_addr, len);
    if (getsockname(fd, (struct sockaddr*)&my_addr, &len) < 0) {
        perror("getsockname error");
        close(fd);
        return -1;
    }
    return ntohs(my_addr.sin_port);
}

void Optimack::open_one_duplicate_conn(std::map<uint, struct subconn_info*> &subconn_info_dict, bool is_backup){
    int ret;

    struct subconn_info *new_subconn = (struct subconn_info *)malloc(sizeof(struct subconn_info));
    memset(new_subconn, 0, sizeof(struct subconn_info));
    //new_subconn->local_port = local_port_new;
    new_subconn->ini_seq_loc = new_subconn->next_seq_loc = 0;
    new_subconn->ini_seq_rem = new_subconn->next_seq_rem = 0;
    new_subconn->last_next_seq_rem = 0;
    // new_subconn->rwnd = 365;
    new_subconn->ack_pacing = ACKPACING;
    new_subconn->ack_sent = 0;
    new_subconn->optim_ack_stop = 1;
    new_subconn->mutex_opa = PTHREAD_MUTEX_INITIALIZER;
    new_subconn->seq_init = false;
    new_subconn->is_backup = is_backup;
    new_subconn->fin_or_rst_recved = false;
    new_subconn->last_data_received = new_subconn->timer_print_log = std::chrono::system_clock::now();
    new_subconn->id = subconn_count++;
    // pthread_mutex_unlock(&mutex_subconn_infos);

    struct sockaddr_in server_addr;

    // Open socket
    if ((new_subconn->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Can't open stream socket.");
        return;
    }

    // unsigned int size =300000/2;
    // if (setsockopt(new_subconn->sockfd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
    //     printf("Error: can't set SOL_SOCKET to %u!\n", size);
    // }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(g_remote_ip);
    server_addr.sin_port = htons(g_remote_port);

    // Connect to server
    if (connect(new_subconn->sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        close(new_subconn->sockfd);
        return;
    }

    struct tcp_info tcp_info;
    socklen_t tcp_info_length = sizeof(tcp_info);
    if ( getsockopt(new_subconn->sockfd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
        printf("S%d: snd_wscale-%u, rcv_wscale-%u, snd_mss-%u, rcv_mss-%u, advmss-%u, %u %u %u %u %u %u %u %u %u %u %u %u\n",
            subconn_count,
            tcp_info.tcpi_snd_wscale,
            tcp_info.tcpi_rcv_wscale,
            tcp_info.tcpi_snd_mss,
            tcp_info.tcpi_rcv_mss,
            tcp_info.tcpi_advmss,
            tcp_info.tcpi_last_data_sent,
            tcp_info.tcpi_last_data_recv,
            tcp_info.tcpi_snd_cwnd,
            tcp_info.tcpi_snd_ssthresh,
            tcp_info.tcpi_rcv_ssthresh,
            tcp_info.tcpi_rtt,
            tcp_info.tcpi_rttvar,
            tcp_info.tcpi_unacked,
            tcp_info.tcpi_sacked,
            tcp_info.tcpi_lost,
            tcp_info.tcpi_retrans,
            tcp_info.tcpi_fackets
            );
    }



    new_subconn->local_port = get_localport(new_subconn->sockfd);
    new_subconn->win_scale = 1 << tcp_info.tcpi_rcv_wscale;
    new_subconn->payload_len = tcp_info.tcpi_advmss;
    // subconn_info_dict[new_subconn->local_port] = new_subconn;
    subconn_infos.insert(std::pair<uint, struct subconn_info*>(new_subconn->local_port, new_subconn));
    log_info("New connection %d established: Port %u", subconn_count-1, new_subconn->local_port);
    // ->push_back(new_subconn); 

    if(BACKUP_MODE){
        backup_port = new_subconn->local_port;
        new_subconn->recved_seq.insertNewInterval_withLock(0,1);
    }

    //TODO: iptables too broad??
    char *cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    // debugs(11, 2, cmd << ret);

    //TODO: iptables too broad??
    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    // debugs(11, 2, cmd << ret);

    // probe seq and ack
    // leave the INPUT rule cleanup to process_tcp_packet
    char dummy_buffer[] = "Hello";
    send(new_subconn->sockfd, dummy_buffer, 5, 0);

    // unsigned int size = 1000;
    // if (setsockopt(new_subconn->sockfd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
    //     int xerrno = errno;
    //     perror("set SO_RCVBUF failed.");
    //     // debugs(50, DBG_CRITICAL, MYNAME << "FD " << new_subconn->sockfd << ", SIZE " << size << ": " << xstrerr(xerrno));
    // }

    //send_SYN(remote_ip, local_ip, remote_port, local_port_new, empty_payload, 0, seq);
    //debugs(1, DBG_IMPORTANT, "Subconn " << i << ": Sent SYN");
}


void 
Optimack::open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, int fd)
{
    printf("New version: CONN_NUM %d, ACK PACE %d\n", CONN_NUM, ACKPACING);

    time_in_HH_MM_SS_nospace(start_time);
    start_timestamp = std::chrono::system_clock::now();

    char* cmd;
    int ret;

    // unsigned int size = 6291456/2;
    // if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
    //     printf("Error: can't set SOL_SOCKET to %u!\n", size);
    // }

    struct tcp_info tcp_info;
    socklen_t tcp_info_length = sizeof(tcp_info);
    if ( getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
        printf("Squid: snd_wscale-%u, rcv_wscale-%u, snd_mss-%u, rcv_mss-%u, advmss-%u, %u %u %u %u %u %u %u %u %u %u %u %u\n",
            tcp_info.tcpi_snd_wscale,
            tcp_info.tcpi_rcv_wscale,
            tcp_info.tcpi_snd_mss,
            tcp_info.tcpi_rcv_mss,
            tcp_info.tcpi_advmss,
            tcp_info.tcpi_last_data_sent,
            tcp_info.tcpi_last_data_recv,
            tcp_info.tcpi_snd_cwnd,
            tcp_info.tcpi_snd_ssthresh,
            tcp_info.tcpi_rcv_ssthresh,
            tcp_info.tcpi_rtt,
            tcp_info.tcpi_rttvar,
            tcp_info.tcpi_unacked,
            tcp_info.tcpi_sacked,
            tcp_info.tcpi_lost,
            tcp_info.tcpi_retrans,
            tcp_info.tcpi_fackets
            );
    }

    main_fd = fd;
    // if marked, let through
    //cmd = (char*) malloc(IPTABLESLEN);
    //sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d -m mark --mark %d -j ACCEPT", remote_ip, remote_port, MARK);
    //ret = exec_iptables('A', cmd);
    //iptables_rules.push_back(cmd);
    //debugs(11, 2, cmd << ret);

    //TODO: iptables too broad??
    cmd = (char*) malloc(IPTABLESLEN);
    // sprintf(cmd, "INPUT -p tcp -s %s --sport %d --dport %d -j DROP", remote_ip, remote_port, local_port);
    sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    // debugs(11, 2, cmd << ret);

    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    // debugs(11, 2, cmd << ret);
 
    strncpy(g_local_ip, local_ip, 16); //TODO: change position
    strncpy(g_remote_ip, remote_ip, 16);
    g_local_ip[15] = 0;
    g_remote_ip[15] = 0;
    inet_pton(AF_INET, local_ip, &g_local_ip_int);
    inet_pton(AF_INET, remote_ip, &g_remote_ip_int);
    g_remote_port = remote_port;
    squid_port = local_port;
    
    dstAddr.sin_family = AF_INET;
    memcpy((char*)&dstAddr.sin_addr, &g_remote_ip_int, sizeof(g_remote_ip_int));

    // char tmp_str[1000];
    // sprintf(mtr_file_name, "mtr_modified_tcp_0.01_100_$(hostname)_%s_%s.txt", g_remote_ip, start_time);
    // sprintf(tmp_str, "screen -dmS mtr bash -c 'while true; do sudo /root/mtr-modified/mtr -zwnr4 -i 0.01 -c 100 -P 80 %s | tee -a %s/%s; done'", g_remote_ip, output_dir, mtr_file_name);
    // system(tmp_str);

    // sprintf(loss_file_name, "ping_0.01_100_$(hostname)_%s_%s.txt", g_remote_ip, start_time);
    // sprintf(tmp_str, "screen -dmS loss_rate bash -c 'cd %s; while true; do echo $(date --rfc-3339=ns): Start >> %s; ping -W 10 -c 100 -i 0.01 -q %s 2>&1 | tee -a %s; echo >> %s; done'", output_dir, loss_file_name, g_remote_ip, loss_file_name, loss_file_name);
    // system(tmp_str);

    pthread_mutex_lock(&mutex_subconn_infos);
    // TODO: how to deal with conns by other applications?
    struct subconn_info *squid_conn = (struct subconn_info *)malloc(sizeof(struct subconn_info));
    if(!squid_conn){
        printf("Can't malloc subconn_info\n");
        return;
    }
    printf("%p\n", squid_conn);
    memset(squid_conn, 0, sizeof(struct subconn_info));
    squid_conn->local_port = local_port;
    squid_conn->ini_seq_loc = squid_conn->next_seq_loc = 0;
    squid_conn->ini_seq_rem = squid_conn->next_seq_rem = 0;
    squid_conn->win_scale = win_scale = 1 << tcp_info.tcpi_rcv_wscale;
    squid_conn->ack_pacing = ACKPACING;
    squid_conn->ack_sent = 1; //Assume squid will send ACK
    squid_conn->optim_ack_stop = 1;
    squid_conn->mutex_opa = PTHREAD_MUTEX_INITIALIZER;
    squid_conn->payload_len = squid_MSS = tcp_info.tcpi_advmss;
    squid_conn->last_data_received = squid_conn->timer_print_log = std::chrono::system_clock::now();
    squid_conn->is_backup = false;
    squid_conn->fin_or_rst_recved = false;
    // if(BACKUP_MODE){
    //     squid_conn->is_backup = true;
    //     backup_port = local_port;
    // }
    squid_conn->id = subconn_count++;
    subconn_infos.clear();
    // subconn_infos.emplace(local_port, squid_conn);
    subconn_infos.insert(std::pair<uint, struct subconn_info*>(local_port, squid_conn));
    // subconn_infos[local_port] = squid_conn;
    // subconn_infos.push_back(squid_conn);
    pthread_mutex_unlock(&mutex_subconn_infos);

    // int conn_num = 3;
    // range
    if (RANGE_MODE) {
        range_sockfd = 0;
    }

    for (int i = 1; i < CONN_NUM; i++) {
        open_one_duplicate_conn(subconn_infos, false);
    }

    if(BACKUP_MODE){
        int backup_num = 1;
        for (int i = 0; i < backup_num; i++) {
            open_one_duplicate_conn(subconn_infos, true);
        }
    }
    log_info("[Squid Conn] port: %d, win_scale %d", local_port, squid_conn->win_scale);
}


int
Optimack::exec_iptables(char action, char* rule)
{
    char cmd[IPTABLESLEN+32];
    sprintf(cmd, "sudo iptables -%c %s", action, rule);
    return system(cmd);
}


int Optimack::insert_to_recv_buffer_withLock(uint seq, unsigned char* data, int len)
{
    unsigned char* payload_recv_buffer = (unsigned char*)malloc(len);
    if(!payload_recv_buffer){
        log_error("insert_to_recv_buffer: can't malloc for data_left");
        return -1;
    }
    memset(payload_recv_buffer, 0, len);
    memcpy(payload_recv_buffer, data, len);
    pthread_mutex_lock(&mutex_recv_buffer);
    auto ret = recv_buffer.insert( std::pair<uint , struct data_segment>(seq, data_segment(payload_recv_buffer, len)) );
    if (ret.second == false) {
        // printf("recv_buffer: %u already existed.\n", seq);
        // log_error("recv_buffer: %u already existed.\n", seq);
        if(ret.first->second.len < len){
            // printf("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            // log_error("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            free(ret.first->second.data);
            ret.first->second.data = NULL;
            recv_buffer.erase(ret.first);
            recv_buffer.insert ( std::pair<uint , struct data_segment>(seq, data_segment(payload_recv_buffer, len)) );
        }
        else{
            free(payload_recv_buffer);
            payload_recv_buffer = NULL;
        }
    }
    else
        log_debug("recv_buffer: insert [%u, %u] len %d", seq, seq+len-1, len);
    pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}

int Optimack::insert_to_recv_buffer(uint seq, unsigned char* data, int len)
{
    unsigned char* payload_recv_buffer = (unsigned char*)malloc(len);
    if(!payload_recv_buffer){
        log_error("insert_to_recv_buffer: can't malloc for data_left");
        return -1;
    }
    memset(payload_recv_buffer, 0, len);
    memcpy(payload_recv_buffer, data, len);
    // pthread_mutex_lock(&mutex_recv_buffer);
    auto ret = recv_buffer.insert( std::pair<uint , struct data_segment>(seq, data_segment(payload_recv_buffer, len)) );
    if (ret.second == false) {
        // printf("recv_buffer: %u already existed.\n", seq);
        // log_error("recv_buffer: %u already existed.\n", seq);
        if(ret.first->second.len < len){
            // printf("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            // log_error("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            free(ret.first->second.data);
            ret.first->second.data = NULL;
            recv_buffer.erase(ret.first);
            recv_buffer.insert ( std::pair<uint , struct data_segment>(seq, data_segment(payload_recv_buffer, len)) );
        }
        else{
            free(payload_recv_buffer);
            payload_recv_buffer = NULL;
        }
    }
    else
        log_debug("recv_buffer: insert [%u, %u] len %d", seq, seq+len-1, len);
    // pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint seq){
    pthread_mutex_lock(&mutex_recv_buffer);
    send_out_of_order_recv_buffer(seq);
    pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint start, uint end, int max_count){
    pthread_mutex_lock(&mutex_recv_buffer);
    send_out_of_order_recv_buffer(start, end, max_count);
    pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint start, uint end){
    pthread_mutex_lock(&mutex_recv_buffer);
    send_out_of_order_recv_buffer(start, end);
    pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer(uint start, uint end, int max_count)
{
    int count = 0;
    // struct subconn_info* squid_conn = subconn_infos[squid_port];
    for(auto it = recv_buffer.begin(); it != recv_buffer.end();it++){
        // log_info("it:[%u, %u], seq %u", it->first, it->first+it->second.len);
        if(it->first <= start && start < it->first+it->second.len-1){
            // send_data_to_squid(it->first, it->second.data, it->second.len);
            // log_info("[ofo]: found first one, send %u, len %d, seq %u", it->first, it->second.len, seq);
            for(auto cur = it; cur != recv_buffer.end() && count < max_count; count++){
                if(cur->first < end){
                    send_data_to_squid(cur->first, cur->second.data, cur->second.len);
                    log_info("[ofo]: send %u, len %d, start %u, end %u", cur->first, cur->second.len, start, end);
                    continue;
                }
                else{
                    log_info("[ofo]: cur %u, break, start %u, end %u", cur->first, start, end);
                    break;
                }
            }
            break;
        }
        else if (it->first > start)
            break;
    }
    log_info("[ofo]: leave send_out_of_order_recv_buffer, start %u, end %u", start, end);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer(uint start, uint end)
{
    // struct subconn_info* squid_conn = subconn_infos[squid_port];
    for(auto it = recv_buffer.begin(); it != recv_buffer.end();it++){
        // log_info("it:[%u, %u], seq %u", it->first, it->first+it->second.len);
        if(it->first <= start && start < it->first+it->second.len-1){
            // send_data_to_squid(it->first, it->second.data, it->second.len);
            // log_info("[ofo]: found first one, send %u, len %d, seq %u", it->first, it->second.len, seq);
            for(auto cur = it; cur != recv_buffer.end(); cur++){
                if(cur->first+cur->second.len <= end){
                    send_data_to_squid(cur->first, cur->second.data, cur->second.len);
                    log_info("[ofo]: send %u, len %d, start %u, end %u", cur->first, cur->second.len, start, end);
                }
                else{
                    log_info("[ofo]: cur %u, break, start %u, end %u", cur->first, start, end);
                    break;
                }
            }
            break;
        }
    }
    log_info("[ofo]: leave send_out_of_order_recv_buffer, start %u, end %u", start, end);
    return 0;
}

int Optimack::send_out_of_order_recv_buffer(uint seq)
{
    // struct subconn_info* squid_conn = subconn_infos[squid_port];
    for(auto it = recv_buffer.begin(); it != recv_buffer.end();it++){
        // log_info("it:[%u, %u], seq %u", it->first, it->first+it->second.len, seq);
        if(it->first <= seq && seq < it->first+it->second.len-1){
            send_data_to_squid(it->first, it->second.data, it->second.len);
            // log_info("[ofo]: found first one, send %u, len %d, seq %u", it->first, it->second.len, seq);
            for(auto prev = it, cur = ++it; prev != recv_buffer.end() && cur != recv_buffer.end(); cur++){
                if(prev->first+prev->second.len >= cur->first && cur->first+cur->second.len <= win_end){
                    send_data_to_squid(cur->first, cur->second.data, cur->second.len);
                    // usleep(10);
                    // log_info("[ofo]: send %u, len %d, seq %u", cur->first, cur->second.len, seq);
                }
                else{
                    // log_info("[ofo]: prev [%u,%u], cur %u, break, seq %u", prev->first, prev->first+it->second.len, cur->first, seq);
                    break;
                }
                recv_buffer.erase(prev);
                prev = cur;
            }
            // recv_buffer.erase(it);
            break;
        }
        else if (it->first > seq)
            break;
    }
    // log_info("[ofo]: leave send_out_of_order_recv_buffer, seq %u", seq);
    return 0;
}

int Optimack::remove_recved_recv_buffer_withLock(uint seq){
    pthread_mutex_lock(&mutex_recv_buffer);
    remove_recved_recv_buffer(seq);
    pthread_mutex_unlock(&mutex_recv_buffer);
    return 0;
}


int Optimack::remove_recved_recv_buffer(uint seq)
{
    struct subconn_info* squid_conn = subconn_infos[squid_port];
    int count = 0;
    for(auto it = recv_buffer.begin(); it != recv_buffer.end();){
        if(it->first+it->second.len-1 < seq){
            log_info("recv_buffer: remove [%u, %u], cur seq %u\n", it->first, it->first+it->second.len-1, seq);
            // log_error("recv_buffer: remove [%u, %u], cur seq %u\n", it->first, it->first+it->second.len-1, seq);
            free(it->second.data);
            it->second.data = NULL;
            recv_buffer.erase(it++);
            continue;
        }
        // else if(it->first < seq){
            // int len_recv = seq-it->first;
            // int len_left = it->second.len - len_recv;
            // // printf("recv_buffer: remove [%u, %u] of [%u, %u], cur seq %u\n", it->first, it->first+len_recv, it->first, it->first+it->second.len, seq);
            // log_info("recv_buffer: remove [%u, %u] of [%u, %u], cur seq %u\n", it->first, it->first+len_recv, it->first, it->first+it->second.len, seq);
            // // log_error("recv_buffer: remove [%u, %u] of [%u, %u], cur seq %u\n", it->first, it->first+len_recv, it->first, it->first+it->second.len, seq);
            // unsigned char* data_left = (unsigned char*) malloc(len_left);
            // if(!data_left){
            //     log_error("remove_recved_recv_buffer: can't malloc for data_left");
            //     return -1;
            // }
            // memset(data_left, 0, len_left);
            // memcpy(data_left, it->second.data+len_recv, len_left);
            // free(it->second.data);
            // it->second.data = NULL;
            // recv_buffer.erase(it++);
            // recv_buffer.insert(std::pair<uint , struct data_segment>(seq, data_segment(data_left, len_left)));
            // send_data_to_squid(it->first, it->second.data, it->second.len);

            // continue;
            // break;
        // }
        // else if (it->first == seq){
            // send_data_to_squid(it->first, it->second.data, it->second.len);
            // break;
        // }
        // else{
            // break;
                // log_error("recv_buffer: [%u, %u] > seq %u, send to squid, seq %u, len %d\n", it->first, it->first+it->second.len, seq, it->first+sent, packet_len);
            // printf("recv_buffer: [%u, %u] > seq %u, break\n", it->first, it->first+it->second.len, seq);
            // log_error("recv_buffer: [%u, %u] > seq %u, send to squid\n", it->first, it->first+it->second.len, it->first);
            // break;
        // }
        break;
        // if(recved_seq.getFirstEnd()-cur_ack_rel <= 10*squid_MSS){
        //         log_error("recv_buffer: [%u, %u] > seq %u, recved_seq(%u)-cur_ack_rel(%u)<%d, break\n", it->first, it->first+it->second.len, seq, recved_seq.getFirstEnd(), cur_ack_rel, 10*squid_MSS);
        //         break;
        // }
        // if (count > 2){
        //     log_error("count > 10, break");
        //     break;
        // }
        // send_data_to_squid(it->first, it->second.data, it->second.len);
        // count++;

        it++;
    }
    return 0;
}

void Optimack::send_data_to_squid(unsigned int seq, unsigned char* payload, int payload_len){
    int packet_len = 0;
    struct subconn_info* squid_conn = subconn_infos[squid_port];
    for(int unsent = payload_len, sent = 0; unsent > 0; unsent -= packet_len, sent += packet_len){
        packet_len = unsent >= squid_MSS? squid_MSS : unsent;
        send_ACK_payload(g_local_ip, g_remote_ip, squid_port, g_remote_port, payload+sent, packet_len, squid_conn->ini_seq_loc + squid_conn->next_seq_loc, squid_conn->ini_seq_rem + seq + sent);
        log_info("send_data_to_squid: seq %u, len %d", seq+sent, packet_len);
        usleep(1);
    }
    // log_seq(forward_seq_file, seq);
}

#ifdef OPENSSL
SSL * Optimack::open_ssl_conn(int fd){
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == nullptr)
    {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return nullptr;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == nullptr)
    {
        fprintf(stderr, "SSL_new() failed\n");
        return nullptr;
    }
    SSL_set_fd(ssl, fd);
    const char* const PREFERRED_CIPHERS = "TLS_AES_128_GCM_SHA256";
    SSL_CTX_set_ciphersuites(ctx, PREFERRED_CIPHERS);
    // SSL_set_ciphersuites(ssl, PREFERRED_CIPHERS);
    const int status = SSL_connect(ssl);
    if (status != 1)
    {
        SSL_get_error(ssl, status);
        fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
        return nullptr;
    }
    // STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    // for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
    //     printf(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    // }
    // printf("\n");
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    // const char *chars = "Hello World, 123!";
    // SSL_write(ssl, chars, strlen(chars));
    // SSL_free(ssl);
    // close(sfd);
    // SSL_CTX_free(ctx);
    return ssl;
}

int Optimack::open_duplicate_ssl_conns(SSL *squid_ssl){
    struct subconn_info* squid_subconn = subconn_infos[squid_port];
    pthread_mutex_lock(&mutex_subconn_infos);
    set_subconn_ssl_credentials(squid_subconn, squid_ssl);
    for(auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
        SSL* ssl = open_ssl_conn(subconn->sockfd);
        set_subconn_ssl_credentials(it->second, ssl);
    }
    pthread_mutex_unlock(&mutex_subconn_infos);
    return 0;
}

int Optimack::set_subconn_ssl_credentials(struct subconn_info *subconn, SSL *ssl){
    unsigned char iv_salt = (unsigned char*)malloc(5);
    unsigned char session_key = (unsigned char*)malloc(33);
    memset(iv_salt,0, 5);
    memset(session_key, 0, 33);
    get_server_session_key_and_iv_salt(ssl, iv_salt, session_key);
    iv_salt[4] = session_key[32] = 0;

    //add info to subconn_infos
    subconn->ssl = ssl;
    subconn->iv_salt = iv_salt;
    subconn->session_key = session_key;
    return 0;
}
#endif

// int main(){
//     //open a connection
//     int sockfd;
//     struct sockaddr_in server_addr;
//     char server_ip[] = "67.205.159.15";

//     // Open socket
//     if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
//         perror("Can't open stream socket.");
//         return -1;
//     }

//     // Set server_addr
//     bzero(&server_addr, sizeof(server_addr));
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_addr.s_addr = inet_addr(server_ip);
//     server_addr.sin_port = htons(80);

//     // Connect to server
//     if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
//         perror("Connect server error");
//         close(sockfd);
//         return -1;
//     }

//     // Get my port
//     struct sockaddr_in my_addr;
//     socklen_t len = sizeof(my_addr);
//     bzero(&my_addr, len);
//     if (getsockname(sockfd, (struct sockaddr*)&my_addr, &len) < 0) {
//         perror("getsockname error");
//         close(sockfd);
//         return 0;
//     }
//     unsigned int local_port = ntohs(my_addr.sin_port);

//     char cmd[128];
//     sprintf(cmd, "sudo iptables -A PREROUTING -t mangle -p tcp -m mark --mark 666 -j ACCEPT");
//     system(cmd);
//     sprintf(cmd, "sudo iptables -A OUTPUT -p tcp -m mark --mark 666 -j ACCEPT");
//     system(cmd);

//     Optimack op;
//     op.init();
//     op.setup_nfq(80);
//     op.nfq_stop = 0;
//     op.setup_nfqloop();
//     op.open_duplicate_conns(server_ip, "167.172.22.132", 80, local_port, sockfd);
//     sleep(4);

//     //send request
//     char request[] = "GET /ubuntu-16.04.6-server-i386.template HTTP/1.1";//\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\nHost: 67.205.159.15\r\nVia: 1.1 NY-DGO-O2C (squid/4.12)\r\nX-Forwarded-For: 127.0.0.1\r\nCache-Control: max-age=259200\r\nConnection: keep-alive\r\n\r\n";
//     if (send(sockfd, request, 50, 0) < 0){
//         printf("Send error\n");
//     }
//     int rv = 1;
//     char buf[1024];
//     while(rv > 0){
//         rv = recv(sockfd, buf, sizeof(buf), 0);
//     }

// }



// int 
// Optimack::find_seq_gaps(unsigned int seq)
// {
//     if (seq < *seq_gaps.begin()[0] || seq > *seq_gaps.end()[1])
//         return 0;
//     return seq_gaps.find(seq) != seq_gaps.end();
//     // for (size_t i = 0; i < seq_gaps.size(); i++)
//     // {
//     //     if (seq < seq_gaps.at(i))
//     //         return -1;
//     //     else if(seq == seq_gaps.at(i))
//     //         return i;
//     // }
//     // return -1;
// }

// void 
// Optimack::insert_seq_gaps(unsigned int start, unsigned int end)
// {
//     printf("insert gap: (%u, %u)\n", start, end);
//     std::vector<uint*>::iterator it;
//     if (seq_gaps.empty()){
//         it = seq_gaps.begin();
//     }
//     else {
//         for (it = seq_gaps.end() ; it != seq_gaps.begin(); --it){
//             if(end < *it[0]) // start < end < *it[0] < *it[1]
//                 continue;
//             else if (end == *it[0]){
//                 printf("end and it.start overlapping: end(%u), it(%u,%u)\n", end, *it[0], *it[1]);
//                 insert_seq_gaps(start, end-1);
//             }

//             if(start > *it[1]) //*it[0] < *it[1] < start < end < *it+1[0]
//                 break;
//             else if (start == *it[1]){
//                 printf("start and it.end overlapping: start(%u), it(%u,%u)\n", start, *it[0], *it[1]);
//                 insert_seq_gaps(start+1, end);
//                 return;
//             }
//             else{// start < *it[1]
//                 if (start >= *it[0])
//                     if(end <= *it[1]) // *it[0] <= start < end <= *it[1], already exists
//                         return;
//                     else{
//                         insert_seq_gaps(*it[1]+1, end); // insert
//                         return;
//                     }
//             }
//         }
//     }
//     uint* gap = new uint[2];
//     gap[0] = start;
//     gap[1] = end;
//     seq_gaps.insert(it, gap);
    
//     // unsigned int last = seq_gaps.at(seq_gaps.size()-1);
//     // if (start > last){
//     //     for(; start < end; start += step)
//     //         seq_gaps.push_back(start);
//     // }
//     // else if (start < last) {
//     //     for(; start < end; start += step){

//     //     }       
//     // }
// }

// void 
// Optimack::delete_seq_gaps(unsigned int val)
// {
//     seq_gaps.erase(val);
// }

// int process_incoming_SYN() {
//     // in this case, pkt must be squid -> server
//     if (subconn_i != -1 && subconn_i != 0){ //subconn_i == -1,正常情况;subconn_i == 0, SYN丢了重传了
//         //debugs(1, DBG_CRITICAL, "subconn_infos != -1/0 when receiving a SYN");
//         return 0;
//     }
//     // build subconn[0] for squid
//     if (subconn_i == -1) {
//         strncpy(local_ip, sip, 16); //TODO: change position
//         strncpy(remote_ip,dip, 16);
//         remote_port = dport;

//         pthread_mutex_lock(&mutex_subconn_infos); //TODO: how to deal with conns by other applications?
//         struct subconn_info new_subconn;
//         new_subconn->local_port = sport;//No nfq callback will interfere because iptable rules haven't been added
//         new_subconn->ini_seq_loc = seq; //unknown
//         new_subconn->next_seq_loc = seq;
//         new_subconn->win_size = 29200*128;
//         new_subconn->ack_pacing = 5000;
//         new_subconn->ack_sent = 1; //Assume squid will send ACK
//         new_subconn->optim_ack_stop = 1;
//         new_subconn->mutex_opa = PTHREAD_MUTEX_INITIALIZER;
//         subconn_infos.push_back(new_subconn);
//         pthread_mutex_unlock(&mutex_subconn_infos);
//     }
//     return 0;
// }

// void process_incoming_SYNACK(){
    //// if server -> squid, init remote seq for squid
    //if(!subconn_i) {
        //if (subconn_infos.size() > 0)
            //subconn_infos.begin()->ini_seq_rem = seq;
        //return 0;
    //}

    //char empty_payload[] = "";
    //send_ACK(sip, dip, sport, dport, empty_payload, seq+1, ack);
    //subconn->ini_seq_rem = subconn->next_seq_rem = seq; //unknown
    ////debugs(1, DBG_IMPORTANT, "S" << subconn_i << ": Received SYN/ACK. Sent ACK");

    //pthread_mutex_lock(&mutex_subconn_infos);
    //subconn->ack_sent = 1;

    //if(!request_recved) {
        //pthread_mutex_unlock(&mutex_subconn_infos);
        //return -1;
    //}

    ////check if all subconns receive syn/ack        
    //size_t i;
    //for (i = 0; i < subconn_infos.size(); i++)
        //if (!subconn_infos[i].ack_sent) {
            //break;
        //}
    //if (i == subconn_infos.size()) {
        //for (size_t i = 0; i < subconn_infos.size(); i++) {
            //send_ACK(sip, dip, sport, subconn_infos[i].local_port, request, subconn_infos[i].ini_seq_rem+1, subconn_infos[i].ini_seq_loc+1);
            //subconn_infos[i].next_seq_loc = subconn_infos[i].ini_seq_loc + 1 + request_len;
        //}
        ////debugs(1, DBG_IMPORTANT, "S" << subconn_i << "All ACK sent, sent request");
    //}
    //pthread_mutex_unlock(&mutex_subconn_infos);


    //return -1;
// }

// int update_global_seq_next_old_vector(){
    // pthread_mutex_lock(&mutex_seq_next_global);
    // int offset = seq_rel - seq_next_global;
    // unsigned int append = 0;
    // if (offset > 0) {
    //     printf("P%d-S%d: > Insert gaps %d -> %d\n", thr_data->pkt_id, subconn_i, seq_next_global, seq_rel);
    //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Insert gaps: " << seq_next_global << ", to: " << seq_rel);
    //     // pthread_mutex_lock(&mutex_seq_gaps);
    //     insert_seq_gaps(seq_next_global, seq_rel, payload_len);
    //     // pthread_mutex_unlock(&mutex_seq_gaps);
    //     append = offset + payload_len;
    // }
    // else if (offset < 0){
        
    //     int ret = find_seq_gaps(seq_rel);
    //     if (!ret){
    //         //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": recv " << seq_rel << " < wanting " << seq_next_global);
    //         pthread_mutex_unlock(&mutex_seq_next_global);
    //         return -1;
    //     }
    //     // pthread_mutex_lock(&mutex_seq_gaps);
    //     delete_seq_gaps(seq_rel);
    //     // pthread_mutex_unlock(&mutex_seq_gaps);
    //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Found gap " << seq_rel << ". Delete gap");
    //     printf("P%d-S%d: < Found gaps %d. Deleted\n", thr_data->pkt_id, subconn_i, seq_rel);
    // }
    // else {
    //     append = payload_len;
    //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Found seg " << seq_rel);
    //     printf("P%d-S%d: = In order %d\n", thr_data->pkt_id, subconn_i, seq_rel);
    // }

    // if(append){
    //     seq_next_global += append;
    //     printf("P%d-S%d: Update seq_next_global to %d\n", thr_data->pkt_id, subconn_i, seq_next_global);
    //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Update seq_global to " << seq_next_global);
    // }
    // pthread_mutex_unlock(&mutex_seq_next_global);
// }

// int update_seq_next_global_old_range_request(){
    // log_debugv("P%d-S%d: process_tcp_packet:1078: mutex_seq_gaps - trying lock", thr_data->pkt_id, subconn_i); 
    // pthread_mutex_lock(&mutex_seq_gaps);
    // if (seq_rel == seq_next_global)
    //     seq_next_global = seq_rel + payload_len;
    // else if (seq_rel > seq_next_global) {
    //     if (RANGE_MODE) {
    //         int start = seq_next_global;
    //         pthread_mutex_lock(&mutex_req_max);
    //         // we allow negative here
    //         // tricky & risky
    //         if (req_max == 0) {
    //             range_sockfd = init_range();
    //             req_max = -1;
    //         }
    //         else
    //             req_max--;
    //         char range_request[MAX_RANGE_REQ_LEN];
    //         memcpy(range_request, request, request_len);
    //         // assume last characters are \r\n\r\n
    //         sprintf(range_request+request_len-2, "Range: bytes=%d-%d\r\n\r\n", start, seq_rel-1);
    //         send(range_sockfd, range_request, strlen(range_request), 0);
    //         pthread_mutex_unlock(&mutex_req_max);
    //     }
    //     seq_gaps = insertNewInterval(seq_gaps, Interval(seq_next_global, seq_rel-1));
    //     seq_next_global = seq_rel + payload_len;
    // }
    // else {
    //     seq_gaps = removeInterval(seq_gaps, Interval(seq_rel, seq_rel+payload_len));
    //     if (seq_next_global < seq_rel + payload_len) //overlap: seq_next_global:100, seq_rel:95, payload_len = 10
    //         seq_next_global = seq_rel + payload_len;
    // }
    // pthread_mutex_unlock(&mutex_seq_gaps);
    // log_debugv("P%d-S%d: process_tcp_packet:1078: mutex_seq_gaps - unlock", thr_data->pkt_id, subconn_i); 

    // if (subconn->optim_ack_stop) {
    //     // TODO: what if payload_len changes?
    //     printf("P%d-S%d: Start optimistic_ack\n", thr_data->pkt_id, subconn_i);
    // }
// }

// void detect_duplicate_retrx_and_restart(){
    // Dup Retrnx
    // else if(seq_rel > 1 && subconn->next_seq_rem >= seq_rel){// && seq > subconn->opa_seq_max_restart && elapsed(last_restart_time) >= 1){ //TODO: out-of-order?
    //     log_info("P%d-S%d: next_seq_rem(%u) >= seq_rel(%u)", thr_data->pkt_id, subconn_i, subconn->next_seq_rem, seq_rel);
    //     //print dup_seqs
    //     if(++subconn->dup_seqs[seq_rel] >= 2){
    //         // subconn->dup_seqs.clear();                       
    //         std::map<uint, uint>::iterator it = subconn->dup_seqs.begin(); 
    //         while (it != subconn->dup_seqs.end()){
    //             if(it->first <= seq_rel){
    //                 it = subconn->dup_seqs.erase(it);
    //             }
    //             else
    //                 it++;
    //         }
    //         //print dup_seqs

    //         //Restart
    //         printf("P%d-S%d: retrx detected %u\n", thr_data->pkt_id, subconn_i, seq_rel);
    //         send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, "", seq, ack, (cur_ack_rel-seq_rel+rwnd)/2048);
    //         restart_optim_ack(subconn_i, seq, ack, payload_len, seq, subconn->last_restart_time);
    //         subconn->next_seq_rem = seq_rel;
    // //         last_restart_time = std::chrono::system_clock::now();

    //     }
    // }
// }
// void retrx_whole_window(){
    //Retrnx the whole window
    // if(subconn->next_seq_rem >= seq_rel && seq >= subconn->opa_seq_max_restart && elapsed(last_restart_time) >= 1){

    //     subconn->opa_retrx_counter++;
    //     if (subconn->opa_retrx_counter >= 3){
    //         subconn->optim_ack_stop = 1;
    //         subconn->ack_pacing += 100;
    //         send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, "", seq, ack, (cur_ack_rel-seq_rel+rwnd)/2048);
    //         // printf("S%d: before join\n", subconn_i);
    //         pthread_join(subconn->thread, NULL);
    //         printf("S%d: Restart optim ack from %u\n", subconn_i, seq_rel);
    //         start_optim_ack(subconn_i, seq, ack, payload_len, subconn->next_seq_rem);//subconn->next_seq_rem
    //         subconn->next_seq_rem = seq_rel;

    //         subconn->opa_retrx_counter = 0;
    //         last_restart_time = std::chrono::system_clock::now();
    //     }
    // }
// }

/** end **/
