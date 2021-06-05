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
#include "Debug.h"
#include "logging.h"
#include "get_server_key.h"

// for http parsing
#include <cstring>
#include <algorithm>
#include "squid.h"
#include "sbuf/SBuf.h"
#include "http/one/RequestParser.h"
#include "http/one/ResponseParser.h"

#include "Optimack.h"


void test_write_key(SSL *s){
    if(!s)
        return;

    unsigned char session_key[20],iv_salt[4];
    get_server_session_key_and_iv_salt(s, session_key, iv_salt);
    // printf("get write iv and salt: %s\n", buf);

    // printf("get server key: %s\n", buf);
}


/** Our code **/
#define ACKPACING 1500
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
                debugs(0, DBG_CRITICAL,"recv() ret " << rv << " errno " << errno);
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
        char* hex_str = hex_dump_str(thr_data->buf, thr_data->len);
        //debugs(0, DBG_CRITICAL, hex_str);
        free(hex_str);
    }

    if (ret == 0){
        nfq_set_verdict(obj->g_nfq_qh, id, NF_ACCEPT, thr_data->len, thr_data->buf);
        //debugs(0, DBG_CRITICAL, "Verdict: Accept");
    }
    else{
        nfq_set_verdict(obj->g_nfq_qh, id, NF_DROP, 0, NULL);
        //debugs(0, DBG_CRITICAL, "Verdict: Drop");
    }

    free(thr_data->buf);
    free(thr_data);
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
    fprintf(out_file, "cat /proc/net/netfilter/nfnetlink_queue:\n%s\n", rst_str.c_str());
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
int Optimack::send_ACK_adjusted_rwnd(struct subconn_info* conn, uint cur_ack){ //std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    if(cur_ack_rel + rwnd < cur_ack_rel)
        printf("Integer overflow: %u+%u = %u\n", cur_ack_rel, rwnd, cur_ack_rel+rwnd);
    
    // cur_win_scale = obj->rwnd / obj->win_scale;
    uint win_end = rwnd/2 + cur_ack_rel;
    int cur_rwnd = win_end - cur_ack ;
    conn->rwnd = cur_rwnd;
    uint cur_win_scaled = cur_rwnd / conn->win_scale;
    if (cur_rwnd <= conn->payload_len*2) {
        send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, cur_ack + conn->ini_seq_rem, conn->opa_seq_start, cur_win_scaled);
        log_info("S%u: sent ack %u, seq %u, win %u, win_end %u, tcp_win %u", conn->local_port, cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_rwnd, win_end, cur_win_scaled);
        return -1;
    }
    else{
        send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, cur_ack + conn->ini_seq_rem, conn->opa_seq_start, cur_win_scaled);
        log_info("S%u: sent ack %u, seq %u, win %u, win_end %u, tcp_win %u", conn->local_port, cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_rwnd, win_end, cur_win_scaled);

    // if(conn->is_backup)
        // printf("obj->rwnd %u, subconn_cur_ack %u, cur_ack_rel %u, conn->rwnd %u\n", obj->rwnd, cur_ack, obj->cur_ack_rel, conn->rwnd);

        // if (conn->is_backup)        
            // printf("O-bu: ack %u, seq %u, win_scaled %d\n", cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_win_scaled);
        return 0;
    }
}


int Optimack::send_optimistic_ack_with_timer(struct subconn_info* conn, uint cur_ack, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
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

void* selective_optimistic_ack(void* arg){
    struct int_thread* ack_thr = (struct int_thread*)arg;
    int id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = (obj->subconn_infos[id]);
    unsigned int opa_seq_start = conn->opa_seq_start;
    unsigned int local_port = conn->local_port, payload_len = conn->payload_len;
    free(ack_thr);

    double send_ack_pace = conn->ack_pacing / 1000000.0;

    std::chrono::time_point<std::chrono::system_clock> last_send_ack, last_data_update, last_log_adjust_rwnd, last_zero_window;
    last_send_ack = last_data_update = last_log_adjust_rwnd = last_zero_window = std::chrono::system_clock::now();
    // bool is_zero_window = true;

    std::set<uint> acks_to_be_sent;
    IntervalList sent_ranges;
    uint last_cur_ack_rel = 1;
    // uint opa_ack_start = 1, opa_ack_end = obj->cur_ack_rel - payload_len;
    uint last_recved_seq = 1;
    while(!conn->optim_ack_stop){

        last_recved_seq = conn->recved_seq.getFirstEnd_withLock();
        // Add optimack ranges
        if(last_recved_seq && obj->cur_ack_rel > last_recved_seq+5*payload_len){
            uint insert_start = last_recved_seq;
            uint sent_range_end = sent_ranges.getLastEnd();
            if (sent_range_end && last_recved_seq < sent_range_end)
                insert_start = sent_range_end;
            for(uint i = insert_start; i < obj->cur_ack_rel; i += payload_len)
                acks_to_be_sent.insert(i);
        }


        //start optimistic ack to recved_seq[0].end, after recved packets to recved_seq[0].end, add [conn->seq_gaps[0].end, obj->recved_seq[0].end]
        if (!acks_to_be_sent.empty() && elapsed(last_send_ack) >= send_ack_pace){
            uint cur_ack = *acks_to_be_sent.begin();
            if(obj->send_optimistic_ack_with_timer(conn, cur_ack, last_send_ack, last_zero_window) >= 0){
                acks_to_be_sent.erase(acks_to_be_sent.begin());
                sent_ranges.insertNewInterval(cur_ack, cur_ack+payload_len);
            }
        }

        // Ignore gaps in optimack_ranges and before
        char tmp[100];
        if(!sent_ranges.getIntervalList().empty()) {
            uint last_recved_seq_end = conn->recved_seq.getLastEnd_withLock();
            if (last_recved_seq_end){// && last_cur_ack_rel != last_recved_seq_end){ //&& inIntervals(sent_ranges, cur_ack_rel)){
                last_cur_ack_rel = last_recved_seq_end;

                uint insert_interval_end = last_recved_seq_end;
                sprintf(tmp, "Padding gaps: last_recved_seq_end-%u, sent_ranges.getLastEnd()-%u", last_recved_seq_end, sent_ranges.getLastEnd());
                if (last_recved_seq_end > sent_ranges.getLastEnd()){
                    insert_interval_end = sent_ranges.getLastEnd();
                    sent_ranges.getIntervalList().clear();
                    for(; !acks_to_be_sent.empty() && *acks_to_be_sent.begin() < last_recved_seq_end; acks_to_be_sent.erase(acks_to_be_sent.begin()));
                    sprintf(tmp, "%s < , ", tmp);
                }
                else if (last_recved_seq_end > sent_ranges.getIntervalList().at(0).start){
                    sent_ranges.removeInterval(1, last_recved_seq_end);
                    sprintf(tmp, "%s > , ", tmp);
                //     insert_interval_end = last_recved_seq_end; 
                }
                // else // last_recved_seq_end < sent_ranges.begin()->start, not in optimack range, but doesn't matter anymore
                //     insert_interval_end = last_recved_seq_end;
                conn->recved_seq.insertNewInterval_withLock(1, insert_interval_end);
                if (is_timeout_and_update(last_log_adjust_rwnd,2)){
                    if(!acks_to_be_sent.empty())
                        printf("%s sent ranges [%u, %u], acks_to_sent[%u, %u]\n", tmp, sent_ranges.getFirstEnd(), sent_ranges.getLastEnd(), *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
                    // conn->recved_seq.printIntervals_withLock();
                }
            } 
        }

        // Overrun detection
        if(is_timeout_and_update(conn->last_data_received, 4)){
            uint ack_restart_start, ack_restart_end;
            if(!sent_ranges.getIntervalList().empty()){
                uint min_ack_sent = sent_ranges.getIntervalList().at(0).start;
                ack_restart_start = std::min(min_ack_sent, last_recved_seq); 
                ack_restart_end = *acks_to_be_sent.begin();
            }
            else {
                ack_restart_start = conn->next_seq_rem - 2*payload_len;
                ack_restart_end = obj->cur_ack_rel;
            }
            if(!acks_to_be_sent.empty())
                printf("O-bu: overrun, restart %u to %u\nBefore: [%u, %u]", ack_restart_start, ack_restart_end, *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
            // std::copy(,acks_to_be_sent.end(), std::ostream_iterator<uint>(std::cout, " "));
            for(uint i = ack_restart_start; i < ack_restart_end; i += payload_len)
                acks_to_be_sent.insert(i);
            if(!acks_to_be_sent.empty())
                printf("\nAfter: [%u, %u]\n", *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
            // delete overruned range from sent_ranges
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
        debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
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
        debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
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
    system("bash ~/squid_copy/src/optimack/test/ks.sh loss_rate");
    system("bash ~/squid_copy/src/optimack/test/ks.sh mtr");
    // pclose(tcpdump_pipe);

    pthread_mutex_lock(&mutex_seq_next_global);
    uint seq_next_global_copy = seq_next_global;
    pthread_mutex_unlock(&mutex_seq_next_global);
    int* counts = new int[seq_next_global_copy/1460+1];
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
    sprintf(tmp_str, "%s/%s", output_dir, info_file_name);
    FILE* info_file = fopen(tmp_str, "w");
    fprintf(info_file, "Start: %s\n", start_time);
    fprintf(info_file, "Stop: %s\n", time_in_HH_MM_SS_nospace(time_str));
    fprintf(info_file, "IP: %s\nPorts: ", g_remote_ip);
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
        fprintf(info_file, "%d, ", it->second->local_port);
    fprintf(info_file, "\n");
    if (RANGE_MODE)
        fprintf(info_file, "Range requested: %u\n", requested_bytes);
    fprintf(info_file, "\n");
    is_nfq_full(info_file);
    fprintf(info_file,"\n");
    fclose(info_file);

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

    printf("Finished writing seq_gaps.\n");
}

void
Optimack::cleanup()
{
    log_info("enter cleanup");

    cb_stop = 1;

    log_seq_gaps();

    if(!overrun_stop){
        overrun_stop++;
        pthread_join(overrun_thread, NULL);
        log_info("overrun_thread exited");    
    }

    if(!range_stop){
        range_stop++;
        pthread_join(range_thread, NULL);
        log_info("range_watch_thread exited");    
    }

    // stop other optimistic_ack threads and close fd
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    // for (size_t i=0; i < subconn_infos.size(); i++) {
        // TODO: mutex?
        if (!it->second->optim_ack_stop) {
            it->second->optim_ack_stop = 1;
            pthread_join(it->second->thread, NULL);
            close(it->second->sockfd);
        }
    }
    log_info("NFQ %d all optimistic threads exited", nfq_queue_num);

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
        free(it->second);
    subconn_infos.clear();
    // clear iptables rules
    for (size_t i=0; i<iptables_rules.size(); i++) {
        exec_iptables('D', iptables_rules[i]);
        free(iptables_rules[i]);
    }
    iptables_rules.clear();
    request_recved = false;
}

Optimack::~Optimack()
{
    log_info("enter destructor");

    // stop nfq_loop thread
    pthread_mutex_lock(&mutex_subconn_infos);
    if(nfq_stop)
        return;

    nfq_stop = 1;
    pthread_join(nfq_thread, NULL);
    log_info("NFQ %d nfq_thread exited", nfq_queue_num);

    cleanup();

     // clear thr_pool
    thr_pool_destroy(pool);
    log_info("destroy thr_pool");
    teardown_nfq();
    log_info("teared down nfq");

    pthread_mutex_destroy(&mutex_seq_next_global);
    pthread_mutex_destroy(&mutex_subconn_infos);
    pthread_mutex_destroy(&mutex_optim_ack_stop);

    pthread_mutex_unlock(&mutex_subconn_infos);
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
        debugs(0, DBG_CRITICAL, "couldn't set mark");
        exit(1);
    }

    int portno = 80;
    sockpacket = open_sockpacket(portno);
    if (sockpacket == -1) {
        debugs(0, DBG_CRITICAL, "[main] can't open packet socket");
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
            debugs(0, DBG_CRITICAL, "couldn't create thr_pool");
            exit(1);                
    }

    char tmp_str[600], time_str[64];
    time_in_YYYY_MM_DD(time_str);
    home_dir = getenv("HOME");
    sprintf(output_dir, "%s/rs/large_file_succ_rate/%s/", home_dir, time_str);
    sprintf(tmp_str, "mkdir -p %s", output_dir);
    system(tmp_str);
    printf("output dir: %s\n", output_dir);

    // char log_file_name[100];
    // sprintf(log_file_name, "/root/off_packet_%s.csv", cur_time.time_in_HH_MM_SS());
    sprintf(tmp_str, "%s/off_packet.csv", output_dir);
    log_file = fopen(tmp_str, "w");
    fprintf(log_file, "time,off_packet_num\n");
    
    sprintf(tmp_str, "%s/rwnd.csv", output_dir);
    rwnd_file = fopen(tmp_str, "w");
    fprintf(rwnd_file, "time,rwnd\n");

    sprintf(tmp_str, "%s/adjust_rwnd.csv", output_dir);
    adjust_rwnd_file = fopen(tmp_str, "w");
    fprintf(adjust_rwnd_file, "time,adjust_rwnd\n");

    // sprintf(tmp_str, "%s/seq.csv", output_dir);
    // seq_file = fopen(tmp_str, "w");
    // fprintf(seq_file, "time,seq_num\n");

    // sprintf(tmp_str, "%s/ack.csv", output_dir);
    // ack_file = fopen(tmp_str, "w");
    // fprintf(ack_file, "time,ack_num\n");


    time_in_HH_MM_SS_nospace(start_time);
    
    // sprintf(seq_gaps_count_file_name, "/root/rs/seq_gaps_count_file_%s.csv", cur_time.time_in_HH_MM_SS());
    sprintf(seq_gaps_count_file_name, "%s/seq_gaps_count_%s.csv", output_dir, start_time);
    // seq_gaps_count_file = fopen(seq_gaps_count_file_name, "a");

    sprintf(info_file_name, "info_%s.txt", start_time);

    sprintf(tmp_str, "%s/lost_per_second.csv", output_dir);
    lost_per_second_file = fopen(tmp_str, "a");   

    last_speedup_time = last_rwnd_write_time = last_restart_time = last_ack_time = std::chrono::system_clock::now();

    nfq_stop = overrun_stop = cb_stop = -1;

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

int 
Optimack::setup_nfq(unsigned short id)
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        debugs(0, DBG_CRITICAL,"error during nfq_open()");
        return -1;
    }

    debugs(0, DBG_CRITICAL,"unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_unbind_pf()");
        return -1;
    }

    debugs(0, DBG_CRITICAL,"binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    nfq_queue_num = id;
    debugs(0, DBG_CRITICAL,"binding this socket to queue " << nfq_queue_num);
    g_nfq_qh = nfq_create_queue(g_nfq_h, nfq_queue_num, &cb, (void*)this);
    if (!g_nfq_qh) {
        debugs(0, DBG_CRITICAL,"error during nfq_create_queue()");
        return -1;
    }
    debugs(0, DBG_CRITICAL,"nfq queue handler: " << g_nfq_qh);

    debugs(0, DBG_CRITICAL,"setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        debugs(0, DBG_CRITICAL,"can't set packet_copy mode");
        return -1;
    }

    unsigned int bufsize = 0x3fffffff, rc = 0;//
    if (nfq_set_queue_maxlen(g_nfq_qh, bufsize/1024) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
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
        debugs(1, DBG_CRITICAL,"Fail to create nfq thread.");
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
    debugs(0, DBG_CRITICAL,"unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    debugs(0, DBG_CRITICAL,"closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_close()");
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
        debugs(0, DBG_CRITICAL, "cb: error during thr_data malloc");
        return -1;
    }
    memset(thr_data, 0, sizeof(struct thread_data));

    // sanity check, could be abbr later
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    // printf("P%d: hook %d\n", ph->packet_id, ph->hook);
    if (!ph) {
        debugs(0, DBG_CRITICAL,"nfq_get_msg_packet_hdr failed");
        return -1;
    }

    thr_data->pkt_id = htonl(ph->packet_id);
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len+1);
    thr_data->obj = obj;
    if (!thr_data->buf){
            debugs(0, DBG_CRITICAL, "cb: error during malloc");
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
        debugs(0, DBG_CRITICAL, "cb: error during thr_pool_queue");
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

    printf("%12s%12u", "next_seq_rem", recved_seq.getFirstEnd_withLock());
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12u", it->second->next_seq_rem);
    }
    printf("\n");

    printf("%12s%12u", "rwnd", rwnd);
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12d", it->second->rwnd);
    }
    printf("\n");
    printf("\n");

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
            head->start = (int)strtol(parse_head, &parse_head, 10);
            parse_head++;
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
    return 0;
}

void*
range_watch(void* arg)
{
    printf("[Range]: range_watch thread starts\n");
    printf("New version\n");
    // printf("test openssl-bio-fetch: %d\n", test_include());
    // get_server_write_key(NULL, NULL);

    int rv, range_sockfd, local_port, remote_port, seq_offset, seq_loc, ini_seq_loc;
    char response[MAX_RANGE_SIZE];
    char data[MAX_RANGE_SIZE];
    char *local_ip, *remote_ip;

    Optimack* obj = ((Optimack*)arg);
    range_sockfd = obj->range_sockfd;
    local_ip = obj->g_local_ip;
    remote_ip = obj->g_remote_ip;
    local_port = obj->subconn_infos.begin()->second->local_port;
    remote_port = obj->g_remote_port;
    seq_offset = obj->subconn_infos.begin()->second->ini_seq_rem;
    seq_loc = obj->subconn_infos.begin()->second->next_seq_loc + obj->subconn_infos.begin()->second->ini_seq_loc;
    ini_seq_loc = obj->subconn_infos.begin()->second->ini_seq_loc;

    // resend pending requests
    int request_len = obj->request_len;
    char request[MAX_RANGE_SIZE];
    pthread_mutex_t *mutex = &(obj->mutex_seq_gaps);
    subconn_info* subconn = (obj->subconn_infos.begin()->second);

    // pthread_mutex_lock(mutex);
    while(true) {

        if(obj->ranges_sent.size() == 0){
            usleep(1000);
            continue;
        }

        obj->init_range();

        memcpy(request, obj->request, request_len);
        std::vector<Interval> range_sent_intervals = obj->ranges_sent.getIntervalList();
        // obj->ranges_sent.printIntervals();
        for(auto it : range_sent_intervals) {
            memset(request+request_len, 0, MAX_RANGE_SIZE-request_len);
            sprintf(request+request_len-2, "Range: bytes=%d-%d\r\n\r\n", it.start, it.end);
            send(range_sockfd, request, strlen(request), 0);
            log_debug("[Range] Resend bytes %d - %d", it.start, it.end);
            // printf("[Range] Resend bytes %d - %d\n", it.start, it.end);
        }
        // pthread_mutex_unlock(mutex);

        int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0, packet_len=0;
        http_header* header = (http_header*)malloc(sizeof(http_header));
        memset(header, 0, sizeof(http_header));
        // parser
        Http1::RequestParser rp;
        SBuf headerBuf;

        do {
            // blocking sock
            if(recv_offset > MAX_RANGE_SIZE){
                printf("recv_offset %d > MAX_RANGE_SIZE %u\n", recv_offset, MAX_RANGE_SIZE);
                break;
            }
            memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset);
            rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, 0);
            // printf("[Range]: rv %d\n", rv);
            if (rv > MAX_RANGE_SIZE)
                printf("[Range]: rv %d > MAX %d\n", rv, MAX_RANGE_SIZE);
            if (rv > 0) {
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
                            printf("[Range]: incomplete http header, len %d\n", unread);
                            break;
                        }
                        else {
                            // parser
                            headerBuf.assign(response+consumed, unread);
                            rp.parse(headerBuf);
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
                            printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->end, header->remain, unread);
                            log_debug("[Range] data retrieved %d - %d", header->start, header->end);
                            // delet completed request
                            //pthread_mutex_lock(&obj->mutex_range);
                            // Interval gap(header->start, header->end);
                            // pthread_mutex_lock(mutex);
                            // for (auto it = subconn->seq_gaps.begin(); it != subconn->seq_gaps.end(); it++) {
                                // if (header->start == (*it).start && header->end + 1 == (*it).end) {
                                    // subconn->seq_gaps = removeInterval(subconn->seq_gaps, Interval(header->start, header->end+1, ""));
                                    // break;
                                // }
                            // }
                            // pthread_mutex_unlock(mutex);
                            //log_debug("[Range] [Warning] pending request not found");
                            //pthread_mutex_unlock(&obj->mutex_range);

                            memcpy(data, response+consumed, header->remain);
                            header->parsed = 0;
                            unread -= header->remain;
                            consumed += header->remain;
                            unsent = header->end - header->start + 1;
                            // parser
                            rp.clear();
                            /*
                            * TODO: send(buf=data, size=unsent) to client here
                            * remove interval gaps (header->start, header->end) here
                            */
                             obj->ranges_sent.removeInterval_withLock(header->start, header->end);
                        }
                        else {
                            // still need more data
                            // we can consume and send all unread data
                            printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->start+unread, header->remain, unread);
                            memcpy(data, response+consumed, unread);
                            header->remain -= unread;
                            consumed += unread;
                            unsent = unread;
                            unread = 0;
                            /*
                            * TODO:
                            * remove interval gaps (header->start, header->start+unread-1) here
                            */
                             obj->ranges_sent.removeInterval_withLock(header->start, header->start+unsent);
                        }

                        int sent;
                        for (sent=0; unsent > 0; sent += packet_len, unsent -= packet_len) {
                            if (unsent >= PACKET_SIZE) {
                                packet_len = PACKET_SIZE;
                            }
                            else {
                                packet_len = unsent;
                            }
                            // obj->ranges_sent.removeInterval_withLock(header->start+sent, header->start+sent+packet_len);
                            uint ack = subconn->ini_seq_loc + subconn->next_seq_loc;
                            uint seq_rel = 1 + obj->response_header_len + header->start + sent;
                            uint seq = subconn->ini_seq_rem +  seq_rel; // Adding the offset back
                            send_ACK_payload(local_ip, remote_ip, local_port, remote_port, (u_char*)(data + sent), packet_len, ack, seq);
                            obj->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+packet_len);
                            log_debug("[Range] retrieved and sent seq %x(%u) ack %x(%u)", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc);
                            // printf ("[Range] retrieved and sent seq %x(%u) ack %x(%u) len %u\n", ntohl(seq), header->start+obj->response_header_len+sent, ntohl(ack), subconn->next_seq_loc, packet_len);
                        }
                        recv_offset = 0;
                        header->start += sent;
                    }
                }
                if (unread < 0)
                    log_debug("[Range] error: unread < 0");
            }
            else if (rv < 0)
                log_debug("[Range] error: ret %d errno %d", rv, errno);
        } while (rv > 0);

        // sock is closed
        close(range_sockfd);
    }

    printf("[Range]: range_watch thread exits...\n");
    pthread_exit(NULL);
}

int
Optimack::init_range()
{
    // int range_sockfd;
    struct sockaddr_in server_addr;

    // Open socket
    if ((range_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Can't open stream socket.");
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(g_remote_ip);
    server_addr.sin_port = htons(g_remote_port);

    // Connect to server
    if (connect(range_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        close(range_sockfd);
    }

    return 0;
}

void Optimack::try_for_gaps_and_request(){
    if(check_packet_lost_on_all_conns()){
        // printf("[Range]: lost on all conns\n");
        Interval lost_range = get_lost_range();
        if(lost_range.start != 0 && lost_range.end != 0){
            // printf("[Range]: Get request range [%u, %u]\n", lost_range.start, lost_range.end);
            send_http_range_request(lost_range);
            requested_bytes += lost_range.end - lost_range.start + 1;
        }
    }
}

bool Optimack::check_packet_lost_on_all_conns(){
    uint seq_recved_global = cur_ack_rel;//TODO: Or ?   obj->recved_seq.getFirstEnd_withLock()

    // for (i = 1; i < num_conns; i++)
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(it->second->next_seq_rem <= seq_recved_global){
            return false;
        }
    }
    return true;
}

Interval Optimack::get_lost_range()
{
    uint min_next_seq_rem = recved_seq.getElem_withLock(1, true);
    // recved_seq.printIntervals();
    if(min_next_seq_rem == 0)
        min_next_seq_rem = -1;
    
    // for (size_t i = 1; i < num_conns; i++)
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
        min_next_seq_rem = std::min(min_next_seq_rem, it->second->next_seq_rem);
    
    if(min_next_seq_rem == -1)
        return Interval(0,0);

    // check if the range has already been sent
    IntervalList lost_range;
    lost_range.insertNewInterval(cur_ack_rel-response_header_len-1, min_next_seq_rem-response_header_len-2);
    lost_range.substract(&ranges_sent);
    if(lost_range.size()){
        return lost_range.getIntervalList().at(0);
    }
    else
        return Interval(0,0);
}

int Optimack::send_http_range_request(Interval range){
    uint start = range.start, end = range.end;
    if (start == end)
        return 0;
    
    char range_request[MAX_RANGE_REQ_LEN];
    memcpy(range_request, request, request_len);
    sprintf(range_request+request_len-2, "Range: bytes=%u-%u\r\n\r\n", start, end);
    ranges_sent.insertNewInterval_withLock(start, end);
    if (send(range_sockfd, range_request, strlen(range_request), 0) < 0){
        // printf("[Range] bytes [%u, %u] failed\n", start, end);
        log_debug("[Range] bytes %d - %d failed", start, end);
        // pthread_join(range_thread, NULL);
        // log_debug("[Range] new range thread created");
        // range_sockfd = init_range(); // Resend the range in range_sent when start a new range watch

        return -1;
    } 
    else{
        // printf("[Range] bytes [%u, %u] requested\n", start, end);
        log_debug("[Range] bytes %d - %d requested", start, end);
        return 0;
    }
}


void* overrun_detector(void* arg){
    Optimack* obj = (Optimack* )arg;
    // std::chrono::time_point<std::chrono::system_clock> *timers = new std::chrono::time_point<std::chrono::system_clock>[num_conns];

    sleep(2);//Wait for the packets to come
    log_info("Start overrun_detector thread");


    auto last_print_seqs = std::chrono::system_clock::now();
    while(!obj->overrun_stop){
        if(is_timeout_and_update(last_print_seqs, 10)){
            obj->print_seq_table();
        }

        if (RANGE_MODE) {
            if(is_timeout_and_update(obj->last_ack_time, 2))
                obj->try_for_gaps_and_request();
        }
        usleep(10);
    }
    // free(timers);
    log_info("overrun_detector thread ends");
    printf("overrun_detector thread ends\n");
    pthread_exit(NULL);
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
    return NULL;
}



int 
Optimack::process_tcp_packet(struct thread_data* thr_data)
{
    char log[LOGSIZE], time_str[64];

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *payload = tcp_payload(thr_data->buf);
    unsigned int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

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
                            log_info("Subconn %d seq_init done", subconn_i);
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
                        if(rwnd > max_win_size)
                            max_win_size = rwnd;
                        this->cur_ack_rel = ack - subconn_infos.begin()->second->ini_seq_rem;
                        log_info("P%d-Squid-out: squid ack %u, win_size %d, max win_size %d, win_end %u", thr_data->pkt_id, cur_ack_rel, rwnd, max_win_size, cur_ack_rel+rwnd);
                        
                        // if (is_timeout_and_update(subconn->timer_print_log, 2))
                        // printf("P%d-Squid-out: squid ack %d, win_size %d, max win_size %d\n", thr_data->pkt_id, cur_ack_rel, rwnd, max_win_size);

                        //Todo: cur_ack_rel < 
                        // subconn_info* subconn_backup = &subconn_infos[subconn_infos.size()-1];
                        // pthread_mutex_lock(&subconn_backup->mutex_seq_gaps);
                        // if(subconn_backup->seq_gaps.size() > 0) {
                        //     printf("O-bu: cur_ack_rel %u, seq_gaps[0].end %u\n", cur_ack_rel, subconn_backup->seq_gaps[0].end);
                        //     if(cur_ack_rel <= subconn_backup->seq_gaps[0].end){
                        //         send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn_backup->local_port, "", subconn_backup->ini_seq_rem + cur_ack_rel, subconn_backup->ini_seq_loc + subconn_backup->next_seq_loc, rwnd/win_scale);
                        //         // if (is_timeout_and_update(timer_print_log, 2))
                        //             printf("O-bu: sent ack %u when recved squid ack\n", cur_ack_rel);
                        //     }
                        // }
                        // // subconn_backup->seq_gaps = insertNewInterval(subconn_backup->seq_gaps, Interval(1, cur_ack_rel, time_in_HH_MM_SS(time_str)));
                        // pthread_mutex_unlock(&subconn_backup->mutex_seq_gaps);

                        log_debugv("P%d-S%d-out: process_tcp_packet:710: mutex_cur_ack_rel - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&mutex_cur_ack_rel);
                        if (cur_ack_rel == last_ack_rel){
                            same_ack_cnt++;
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
                            last_ack_rel = cur_ack_rel;
                        }
                        pthread_mutex_unlock(&mutex_cur_ack_rel);
                        log_debugv("P%d-S%d-out: process_tcp_packet:710: mutex_cur_ack_rel - unlock", thr_data->pkt_id, subconn_i); 

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
                        log_debugv("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
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
                                log_error("Fail to create overrun_detector thread.");
                        }
                        log_info("P%d-Squid-out: sent request to all connections", thr_data->pkt_id);
                        seq_next_global = 1;
                        pthread_mutex_unlock(&mutex_subconn_infos);
                        log_debugv("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                        if(RANGE_MODE){
                            range_stop = 0;
                            if (pthread_create(&range_thread, NULL, range_watch, (void *)this) != 0) {
                                //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
                                perror("Can't create range_watch thread\n");
                                return -1;
                            }
                        }
                    }
                    else{
                            log_info("P%d-S%d-out: ack %u, win %d", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_rem, ntohs(tcphdr->th_win) * subconn->win_scale);
                    }
                    return -1;
                    break;
                }
            default:
                log_debug("[default passed] P%d-S%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d", thr_data->pkt_id, subconn_i, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq-subconn->ini_seq_rem, tcphdr->th_ack, ack-subconn->ini_seq_loc, iphdr->ttl, payload_len);
                return 0;
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

            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
            {
                if (!payload_len) {
                    // TODO: let our reply through...for now
                    if (subconn_i)
                        return 0;
                    log_info("P%d-S%d-in: server or our ack %u", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_loc);
                    return -1;
                }

                // if(!subconn->payload_len && subconn->optim_ack_stop){
                if(subconn->optim_ack_stop){
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                    pthread_mutex_lock(&subconn->mutex_opa);
                    if(subconn->optim_ack_stop){
                        // if(BACKUP_MODE){
                        if(subconn->is_backup){
                                //Start backup listening thread
                            start_optim_ack_backup(local_port, subconn->ini_seq_rem + 1, subconn->next_seq_loc+subconn->ini_seq_loc, payload_len, 0); //TODO: read MTU
                            // printf("S%d: Backup connection, not optim ack\n", subconn_i);
                        }
                        // }
                        else{
                            // subconn->payload_len = payload_len;
                            // subconn_infos.begin()->payload_len = payload_len;
                            // if(subconn_i){
                            if(true){
                                start_optim_ack(local_port, subconn->ini_seq_rem + 1, subconn->next_seq_loc+subconn->ini_seq_loc, payload_len, 0); //TODO: read MTU
                                printf("P%d-S%d: Start optimistic_ack\n", thr_data->pkt_id, subconn_i);
                            }
                        }
                    }
                    pthread_mutex_unlock(&subconn->mutex_opa);
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                }

                if(overrun_stop == -1) {
                    log_debugv("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
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
                    log_debugv("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                }

                if(seq_rel == 1 && local_port == squid_port){
                    Http1::ResponseParser rp;
                    SBuf headerBuf;
                    headerBuf.assign((char*)payload, payload_len);
                    rp.parse(headerBuf);
                    response_header_len = rp.messageHeaderSize();
                    printf("[Range]: Server response - headBlockSize %d StatusCode %d\n", response_header_len, rp.parseStatusCode);
                    // printf("seq in this conn-%u, file byte-%u, %c\n", seq_rel+response_header_len, 0, payload[response_header_len+1]);
                    // src/http/StatusCode.h
                }

                // if(!subconn_i){
                //     fprintf(seq_file, "%s, %u\n", time_in_HH_MM_SS_US(time_str), seq_rel);
                // }
                
                pthread_mutex_lock(&mutex_seq_next_global);
                // bytes_per_second[time_in_HH_MM_SS(time_str)] += seq_rel + payload_len - subconn->next_seq_rem;
                sprintf(log, "%s - cur seq_next_global %u", log, seq_next_global);
                if (seq_next_global < seq_rel + payload_len)
                    seq_next_global = seq_rel + payload_len;
                sprintf(log,"%s - update seq_next_global to %u", log, seq_next_global);
                pthread_mutex_unlock(&mutex_seq_next_global);

                pthread_mutex_lock(&subconn->mutex_opa);
                sprintf(log, "%s - cur next_seq_rem %u", log, subconn->next_seq_rem);
                if (subconn->next_seq_rem < seq_rel + payload_len) {//overlap: seq_next_global:100, seq_rel:95, payload_len = 10
                    subconn->next_seq_rem = seq_rel + payload_len;
                    subconn->last_data_received = std::chrono::system_clock::now();
                }
                sprintf(log,"%s - update next_seq_rem to %u", log, subconn->next_seq_rem);
                pthread_mutex_unlock(&subconn->mutex_opa);

                recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+payload_len);
                subconn->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+payload_len);
                    // printf("%s - insert interval[%u, %u]\n", time_str, subconn->next_seq_rem, seq_rel);
                    // log_debug(Intervals2str(subconn->seq_gaps).c_str());
                    // log_info("%d, [%u, %u]", subconn_i, subconn->next_seq_rem, seq_rel);
                    // sprintf(log,"%s - insert interval[%u, %u]", log, subconn->next_seq_rem, seq_rel);



                if (subconn->is_backup){
                    //Normal Mode
                    char *empty_payload = "";
                    pthread_mutex_lock(&subconn->mutex_opa);
                    uint inorder_seq_end = subconn->recved_seq.getFirstEnd_withLock();// subconn->seq_gaps[0].end;
                    if (inorder_seq_end > cur_ack_rel)
                        inorder_seq_end = cur_ack_rel;
                    int cur_win_scale = (cur_ack_rel + rwnd - inorder_seq_end + subconn->ini_seq_rem) / win_scale;
                    if (cur_win_scale > 0) {
                        if(seq_rel == 1 && payload_len != subconn->payload_len){
                            send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + 1 + payload_len, ack, cur_win_scale);
                            sprintf(log, "%s - Sent ack %u", log, 1 + payload_len);
                        }
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
                    }
                    pthread_mutex_unlock(&subconn->mutex_opa);
                }

                if(payload_len != subconn_infos.begin()->second->payload_len){
                    sprintf(log, "%s - unusal payload_len!%d-%d", log, payload_len, subconn_infos.begin()->second->payload_len);
                    send_ACK_adjusted_rwnd(subconn, seq_rel + payload_len);
                    // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + seq_rel + payload_len, ack, (cur_ack_rel + rwnd/2 - seq_rel - payload_len)/subconn->win_scale);
                }

                //Too many packets forwarded to squid will cause squid to discard right most packets
                if (seq_rel + payload_len <= cur_ack_rel) {
                    // printf("P%d-S%d: discarded\n", thr_data->pkt_id, subconn_i); 
                    log_debug("%s - discarded", log);
                    return -1;
                }

                if (seq_rel >= cur_ack_rel + rwnd){
                    // sprintf(log, "%s - Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u", log, seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    log_info("Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u", seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    printf("Out-of-window packet: seq_rel %u >= cur_ack_rel %u + rwnd %d = %u\n", seq_rel, cur_ack_rel, rwnd, cur_ack_rel+rwnd);
                    // sleep(1);
                }
                // // send to squid 
                // // 1. dest port -> sub1->localport
                // // 2. seq -> sub1->init_seq_rem + seq_rel
                // // 3. ack -> sub1->next_seq_loc
                // // 4. checksum(IP,TCP)
                // if (is_timeout_and_update(subconn->timer_print_log, 2))
                //     printf("%s - forwarded to squid\n", log);
                log_debug("%s - forwarded to squid", log); 
                if(!subconn_i)//Main subconn, return directly
                    return 0; 
#ifdef OPENSSL
                //find 
                //decrypt packet
                //encrypt packet
#endif
                tcphdr->th_dport = htons(subconn_infos.begin()->second->local_port);
                tcphdr->th_seq = htonl(subconn_infos.begin()->second->ini_seq_rem + seq_rel);
                tcphdr->th_ack = htonl(subconn_infos.begin()->second->ini_seq_loc + subconn_infos.begin()->second->next_seq_loc);
                compute_checksums(thr_data->buf, 20, thr_data->len);
                // send_ACK_payload(g_local_ip, g_remote_ip,subconn_infos.begin()->local_port, g_remote_port, payload, payload_len,subconn_infos.begin()->ini_seq_loc + subconn_infos.begin()->next_seq_loc, subconn_infos.begin()->ini_seq_rem + seq_rel);
                // sleep(1);
                // usleep(10000);
                // printf("P%d-S%d: forwarded to squid\n", thr_data->pkt_id, subconn_i); 
                // if(rand() % 100 < 50)
                    return 0;
                break;
            }
            case TH_ACK | TH_FIN:
            case TH_ACK | TH_FIN | TH_PUSH:
            {
                printf("S%d: Received FIN/ACK. Sent FIN/ACK. %u\n", subconn_i, seq-subconn->ini_seq_rem);
                log_info("S%d: Received FIN/ACK. Sent FIN/ACK.", subconn_i);
                // send_FIN_ACK(g_local_ip, g_remote_ip, subconn->local_port, g_remote_port, "", seq+1, ack+1);
                subconn->fin_ack_recved = true;

                log_debugv("P%d-S%d: process_tcp_packet:1386: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                pthread_mutex_lock(&mutex_subconn_infos);    
                if(!subconn->optim_ack_stop){
                    subconn->optim_ack_stop = 1;
                    // pthread_join(subconn->thread, NULL);
                    close(subconn->sockfd);
                }

                if(!overrun_stop){    
                    std::map<uint, struct subconn_info*>::iterator it;

                    // for (i = 0; i < subconn_infos.size(); i++)
                    for (it = subconn_infos.begin(); it != subconn_infos.end(); it++)
                        if (!it->second->fin_ack_recved) {
                            break;
                        }
                    if (it == subconn_infos.end()){
                        printf("All subconns received FIN/ACK!\n");
                        close(main_fd);
                        send_RST(g_remote_ip, g_local_ip, g_remote_port, subconn_infos.begin()->second->local_port, "", subconn_infos.begin()->second->ini_seq_rem+cur_ack_rel);
                        printf("RST sent\n");
                        
                        if(!overrun_stop){
                            printf("stop overrun thread\n");
                            overrun_stop++;
                        //     pthread_join(overrun_thread, NULL);  
                        }
                        //TODO: close nfq_thread
                        // TODO: cleanup iptables or cleanup per subconn                               
                    }
                }
                pthread_mutex_unlock(&mutex_subconn_infos);                               
                log_debugv("P%d-S%d: process_tcp_packet:1386: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 

                return -1;
                break;
            }
            default:
                // printf("P%d-S%d: Invalid tcp flags: %s\n", thr_data->pkt_id, subconn_i, tcp_flags_str(tcphdr->th_flags));
                break;
        }
        return -1;
    }
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
    new_subconn->fin_ack_recved = false;
    new_subconn->is_backup = is_backup;
    new_subconn->last_data_received = new_subconn->timer_print_log = std::chrono::system_clock::now();
    new_subconn->id = subconn_count++;
    // pthread_mutex_unlock(&mutex_subconn_infos);

    struct sockaddr_in server_addr, my_addr;

    // Open socket
    if ((new_subconn->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Can't open stream socket.");
        return;
    }

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


    // Get my port
    socklen_t len = sizeof(my_addr);
    bzero(&my_addr, len);
    if (getsockname(new_subconn->sockfd, (struct sockaddr*)&my_addr, &len) < 0) {
        perror("getsockname error");
        close(new_subconn->sockfd);
        return;
    }
    new_subconn->local_port = ntohs(my_addr.sin_port);
    new_subconn->win_scale = 1 << tcp_info.tcpi_rcv_wscale;
    new_subconn->payload_len = tcp_info.tcpi_advmss;
    // subconn_info_dict[new_subconn->local_port] = new_subconn;
    subconn_infos.insert(std::pair<uint, struct subconn_info*>(new_subconn->local_port, new_subconn));
    log_info("New connection %d established: Port %u", subconn_count-1, new_subconn->local_port);
    // ->push_back(new_subconn); 

    //TODO: iptables too broad??
    char *cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    debugs(11, 2, cmd << ret);

    //TODO: iptables too broad??
    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    debugs(11, 2, cmd << ret);

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
    char* cmd;
    int ret;

    struct tcp_info tcp_info;
    socklen_t tcp_info_length = sizeof(tcp_info);
    if ( getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
        printf("snd_wscale-%u, rcv_wscale-%u, snd_mss-%u, rcv_mss-%u, advmss-%u, %u %u %u %u %u %u %u %u %u %u %u %u\n",
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
    debugs(11, 2, cmd << ret);

    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    debugs(11, 2, cmd << ret);
 
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

    char tmp_str[1000];
    
    sprintf(mtr_file_name, "mtr_modified_tcp_0.01_100_$(hostname)_%s_%s.txt", g_remote_ip, start_time);
    // sprintf(tmp_str, "screen -dmS mtr bash -c 'while true; do sudo /root/mtr-modified/mtr -zwnr4 -i 0.01 -c 100 -P 80 %s | tee -a %s/%s; done'", g_remote_ip, output_dir, mtr_file_name);
    // system(tmp_str);

    sprintf(loss_file_name, "ping_0.01_100_$(hostname)_%s_%s.txt", g_remote_ip, start_time);
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
    squid_conn->win_scale = 1 << tcp_info.tcpi_rcv_wscale;
    squid_conn->ack_pacing = ACKPACING;
    squid_conn->ack_sent = 1; //Assume squid will send ACK
    squid_conn->optim_ack_stop = 1;
    squid_conn->mutex_opa = PTHREAD_MUTEX_INITIALIZER;
    squid_conn->fin_ack_recved = false;
    squid_conn->payload_len = tcp_info.tcpi_advmss;
    squid_conn->last_data_received = squid_conn->timer_print_log = std::chrono::system_clock::now();
    squid_conn->is_backup = false;
    if(BACKUP_MODE)
        squid_conn->is_backup = true;
    squid_conn->id = subconn_count++;
    subconn_infos.clear();
    // subconn_infos.emplace(local_port, squid_conn);
    subconn_infos.insert(std::pair<uint, struct subconn_info*>(local_port, squid_conn));
    // subconn_infos[local_port] = squid_conn;
    // subconn_infos.push_back(squid_conn);
    pthread_mutex_unlock(&mutex_subconn_infos);

    int conn_num = 4;
    // range
    if (RANGE_MODE) {
        range_sockfd = 0;
    }

    for (int i = 1; i <= conn_num; i++) {
        open_one_duplicate_conn(subconn_infos, false);
    }

    int backup_num = 0;
    for (int i = 0; i < backup_num; i++) {
        open_one_duplicate_conn(subconn_infos, true);
    }
    log_info("[Squid Conn] port: %d", local_port);
}


int
Optimack::exec_iptables(char action, char* rule)
{
    char cmd[IPTABLESLEN+32];
    sprintf(cmd, "sudo iptables -%c %s", action, rule);
    return system(cmd);
}

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
