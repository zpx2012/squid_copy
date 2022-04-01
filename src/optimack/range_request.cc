#include <string.h>
#include <algorithm>
#include <arpa/inet.h> //ntohl
#include <unistd.h> //close
#include <netinet/in.h>

#include "squid.h"
#include "sbuf/SBuf.h"
#include "http/one/RequestParser.h"
#include "http/one/ResponseParser.h"


#include "logging.h"
#include "Optimack.h"

// range
#define MAX_REQUEST_LEN 1024
#define MAX_RANGE_REQ_LEN 1536
#define MAX_RANGE_SIZE 20000
#define PACKET_SIZE 1460

struct http_header {
    int start;
    int end;
    int parsed;
    int remain;
    int recved;
};

const char header_field[] = "HTTP/1.1 206";
const char range_field[] = "Content-Range: bytes ";
const char tail_field[] = "\r\n\r\n";
const char keep_alive_field[] = "Keep-Alive: ";
const char max_field[] = "max=";

int process_range_rv(char* response, int rv, Optimack* obj, subconn_info* subconn, std::vector<Interval> range_job_vector, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);
void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);


int parse_response(http_header *head, char *response, int unread)
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
                    head->recved = 0;
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


void*
range_watch(void* arg)
{
    printf("[Range]: range_watch thread starts\n");

#ifdef USE_OPENSSL
    SSL *range_ssl, *range_ssl_old;
#endif

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

        obj->try_for_gaps_and_request();

        if(range_job_vector.size() == 0){
            // printf("range_job_vector.size() == 0\n");
            continue;
        }

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
            if(obj->is_ssl){
#ifdef USE_OPENSSL
                range_ssl = open_ssl_conn(range_sockfd, false);
                SSL_free(range_ssl_old);
                fcntl(range_sockfd, F_SETFL, O_NONBLOCK);
#endif
            }
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
            uint end_tcp_seq = obj->get_tcp_seq(it->end);
            if (obj->cur_ack_rel >= end_tcp_seq){
                erase_count++;
                log_info("[Range] cur_ack_rel %u >= it->end %u, delete\n", obj->cur_ack_rel, end_tcp_seq);
                printf("[Range] cur_ack_rel %u >= it->end %u, delete, erase count %d\n", obj->cur_ack_rel, end_tcp_seq, erase_count);
                // printf("before erase it: [%u, %u]\n", it->start, it->end);
                range_job_vector.erase(it++);
                if(!range_job_vector.size())
                    break;
                // printf("after erase it: [%u, %u]\n", it->start, it->end);
                continue;
            }
            if(!it->sent_epoch_time){
                if(obj->is_ssl)
#ifdef USE_OPENSSL
                    obj->send_http_range_request(range_ssl, *it);
#endif
                else
                    obj->send_http_range_request((void*)range_sockfd, *it);

                it->sent_epoch_time = get_current_epoch_time_second();
                // printf("[Range]: sent range[%u, %u]\n", it->start+obj->response_header_len+1, it->end+obj->response_header_len+1);
            }
            else if (get_current_epoch_time_nanosecond() - it->sent_epoch_time >= 10){//timeout, send it again
                double delay = get_current_epoch_time_nanosecond() - it->sent_epoch_time;
                obj->range_timeout_cnt++;
                obj->range_timeout_penalty += delay;
                uint start_tcp_seq = obj->get_tcp_seq(it->start);
                log_info("[Range] [%u, %u] timeout %.2f, close and restart\n", start_tcp_seq, end_tcp_seq, delay);
                printf("[Range] [%u, %u] timeout %.2f, close and restart\n", start_tcp_seq, end_tcp_seq, delay);
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
        if(recv_offset == 0)
            memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset+1);
        if(obj->is_ssl){
#ifdef USE_OPENSSL
            rv = SSL_read(range_ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
#endif
        }
        else{
            rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);
        }

        if (rv > 0) {
            log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
            printf("[Range] recved %d bytes, hand over to process_range_rv\n", rv);
            process_range_rv(response, rv, obj, subconn, range_job_vector, header, consumed, unread, parsed, recv_offset, unsent);
        }
        else if(rv == 0){
            if(!obj->is_ssl){
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
            }

            if(rv == 0){
                log_debug("[Range] recv ret %d, sockfd %d closed ", rv, range_sockfd);
                printf("[Range] recv ret %d, sockfd %d closed\n", rv, range_sockfd);
            }
            else{
                log_debug("[Range] error: ret %d errno %d", rv, errno);
                printf("[Range] error: ret %d errno %d\n", rv, errno);
            }
            cleanup_range(range_sockfd, range_sockfd_old, header, consumed, unread, parsed, recv_offset, unsent);
            printf("closed range_sockfd %d\n", range_sockfd);
#ifdef USE_OPENSSL
            if(obj->is_ssl)
                range_ssl_old = range_ssl;
#endif
        }
        usleep(100);
    }
    free(header);
    header = NULL;

    printf("[Range]: range_watch thread exits...\n");
    pthread_exit(NULL);
}


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

        // if(elapsed(last_ack_time) > MAX_STALL_TIME){
            // char time_str[20] = "";
            // printf("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
            // log_info("try_for_gaps_and_request: Reach max stall time, last ack time %s exit...\n", print_chrono_time(last_ack_time, time_str));
            
        // }
    }

    if(check_packet_lost_on_all_conns(recved_seq.getFirstEnd())){
        // printf("[Range]: lost on all conns\n");
        // lost_range [recved_seq[0].end, recved_seq[1].end]
        // Interval lost_range = get_lost_range();
        uint first_out_of_order = recved_seq.getElem_withLock(1,true);// ;getIntervalList().at(1).start
        if(is_ssl){
#ifdef USE_OPENSSL
            uint second_end = recved_seq.getElem_withLock(1,false);
            if(second_end == first_out_of_order)
                return;
#endif
        }
        if(first_out_of_order){
            Interval lost_all_range(recved_seq.getFirstEnd(), first_out_of_order-1);
            if(get_lost_range(&lost_all_range) >= 0){
                ranges_sent.insert(lost_all_range);
                log_info("lost on all: request range[%u, %u]",lost_all_range.start+ response_header_len + 1, lost_all_range.end + response_header_len + 1);
                // start_range_recv(intervallist);
            }
        }
    }
}


bool Optimack::check_packet_lost_on_all_conns(uint last_recv_inorder){
    // uint seq_recved_global = recved_seq.getFirstEnd_withLock();//TODO: Or ?  cur_ack_rel
    if (recved_seq.size() < 2)
        return false;

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        // log_info("first: recved_seq.lastend %u, last_recv_inorder %u", it->second->recved_seq.getLastEnd(), last_recv_inorder);
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && it->second->next_seq_rem <= last_recv_inorder){
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
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && it->second->next_seq_rem <= last_recv_inorder){
            log_info("second: %s, <=, return false", tmp);
            return false;
        }
    }
    // sprintf(tmp, "%s recved_seq.FirstEnd:%u", tmp, recved_seq.getFirstEnd());
    // log_info("lost on all: %s", tmp);
    return true;
}


int process_range_rv(char* response, int rv, Optimack* obj, subconn_info* subconn, std::vector<Interval> range_job_vector, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    if (rv > MAX_RANGE_SIZE)
        printf("[Range]: rv %d > MAX %d\n", rv, MAX_RANGE_SIZE);

    // char data[MAX_RANGE_SIZE+1];
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
            // if (header->remain <= unread) {
            //     // we have all the data
            //     // printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start, header->end, header->remain, unread);
            //     log_error("[Range] data retrieved %d - %d", header->start, header->end);
            //     printf("[Range] data retrieved %d - %d\n", header->start, header->end);

            //     memcpy(data, response+consumed, header->remain);
            //     header->parsed = 0;
            //     unread -= header->remain;
            //     consumed += header->remain;
            //     unsent = header->end - header->start + 1;
            //     // parser
            //     // rp.clear();
            //     /*
            //     * TODO: send(buf=data, size=unsent) to client here
            //     * remove interval gaps (header->start, header->end) here
            //     */
            //     // range_job->removeInterval(header->start, header->end);
            //     log_error("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
            //     printf("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
            //     obj->ranges_sent.removeInterval(header->start, header->end);
            //     log_error("After removing [%u, %u], %s", header->start, header->end, obj->ranges_sent.Intervals2str().c_str());
            //     printf("After removing [%u, %u], %s\n", header->start, header->end, obj->ranges_sent.Intervals2str().c_str());
            // }
            // else {
                // still need more data
                // we can consume and send all unread data
                printf("[Range] data retrieved %d - %d, remain %d, unread %d\n", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
                log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
                // memcpy(data, response+consumed, unread);
                // header->remain -= unread;
                // consumed += unread;
                // unsent = unread;
                // unread = 0;
            // }

            int sent, packet_len;//rename to byte_len
            int send_data_len = 0;//rename to tcp_len
            uint ack, seq, seq_rel;
            for (sent=0; unread > 0; ) {
                ack = subconn->ini_seq_loc + subconn->next_seq_loc;
                seq_rel = obj->get_tcp_seq(header->start + header->recved);
                seq = subconn->ini_seq_rem + seq_rel; // Adding the offset back

                unsigned char* send_data = (u_char*)(response + consumed);

                if(obj->is_ssl){
#ifdef USE_OPENSSL
                    packet_len = MAX_FRAG_LEN;
                    if(unread < MAX_FRAG_LEN)
                        if(header->remain > unread)
                            break;
                        else{
                            packet_len = unread;
                            printf("[Range] packet length(%u) not equal to MAX_FRAG_LEN\n", unread);
                            if(seq_rel+packet_len != obj->ack_end)
                                break;
                        }
                    // packet_len = unsent >= MAX_FRAG_LEN? MAX_FRAG_LEN : unsent;
                    // printf("Range plaintext: seq %u\n", header->start + sent);
                    // print_hexdump(cur_data, packet_len);

                    unsigned char ciphertext[MAX_FULL_GCM_RECORD_LEN+1] = {0};
                    int ciphertext_len = subconn->crypto_coder->generate_record(get_record_num(seq_rel), send_data, packet_len, ciphertext);
                    send_data = ciphertext;
                    send_data_len = ciphertext_len;
                    // printf("Range ciphertext: seq %u\n", seq_rel);
                    // print_hexdump(ciphertext, packet_len);
#endif
                }
                else{
                    packet_len = obj->squid_MSS;
                    if(unread < obj->squid_MSS)
                        if(header->remain > unread)
                            break;
                        else
                            packet_len = unread;
                    // packet_len = unsent >= obj->squid_MSS? obj->squid_MSS : unsent;
                    send_data_len = packet_len;
                }

                obj->recved_seq.insertNewInterval_withLock(seq_rel, seq_rel+send_data_len);
                log_debug("[Range] insert [%u,%u] to recved_seq, after %s", seq_rel, seq_rel+send_data_len, obj->recved_seq.Intervals2str().substr(0,490).c_str());

                obj->all_lost_seq.insertNewInterval_withLock(seq_rel, seq_rel+send_data_len);
                log_debug("[Range] insert [%u,%u] to all_lost_seq", seq_rel, seq_rel+send_data_len);
     
                // remove interval gaps (header->start, header->start+unread-1) here
                // range_job->removeInterval(header->start, header->start+unsent);
                // log_error("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                // printf("[Range] ranges_sent before %s", obj->ranges_sent.Intervals2str().c_str());
                //TODO: not start
                obj->ranges_sent.removeInterval_updateTimer(header->start+header->recved, header->start+header->recved+send_data_len);
                log_error("After removing [%u, %u], %s", header->start+header->recved, header->start+header->recved+send_data_len, obj->ranges_sent.Intervals2str().c_str());
                // printf("After removing [%u, %u], %s\n", header->start, header->start+unsent, obj->ranges_sent.Intervals2str().c_str());


                obj->send_data_to_squid(seq_rel, send_data, send_data_len);
                log_debug("[Range] retrieved and sent seq %x(%u) ack %x(%u) len %u", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc, send_data_len);
                printf("[Range] retrieved and sent seq %x(%u) ack %x(%u) len %u\n", ntohl(seq), seq_rel, ntohl(ack), subconn->next_seq_loc, send_data_len);

                header->recved += packet_len;
                header->remain -= packet_len;
                consumed += packet_len;
                unread -= packet_len;
                sent += packet_len;
            }
            obj->send_out_of_order_recv_buffer_withLock(seq_rel + send_data_len);
            recv_offset = unread;
            memcpy(response, response+consumed, unread);
            // header->start += sent;
            break;
        }
    }

    if(unread == 0 && header->remain == 0)
        header->parsed = 0;

    if (unread < 0){
        log_debug("[Range] error: unread < 0");
        return -1;
    }
    if(recv_offset >= MAX_RANGE_SIZE){
        printf("recv_offset %d > MAX_RANGE_SIZE %u\n", recv_offset, MAX_RANGE_SIZE);
        return -1;
    }
    return 0;
}


int Optimack::get_lost_range(Interval* intvl)
{
    uint start = get_byte_seq(intvl->start), end = get_byte_seq(intvl->end);
    if(start == -1 || end == -1)
        return -1;
    

    // check if the range has already been sent
    IntervalList lost_range;
    lost_range.clear();
    lost_range.insertNewInterval(start, end);
    lost_range.substract(&ranges_sent);
    if(lost_range.size()){
        printf("[Range]: get lost range, tcp_seq[%u, %u], byte_seq[%u, %u], tcp_seq[%u, %u]\n", intvl->start, intvl->end, start, end, get_tcp_seq(start), get_tcp_seq(end));
        intvl->start = lost_range.getIntervalList().at(0).start;
        intvl->end = lost_range.getIntervalList().at(0).end;
#ifdef USE_OPENSSL
        if(is_ssl)
            if((intvl->end != ack_end) && (intvl->end - intvl->start + 1) % MAX_FRAG_LEN != 0){
                printf("get_lost_range: len(%u)%%d != 0\n", intvl->end-intvl->start+1, MAX_FRAG_LEN);
                return -1;
                uint recordnum = (intvl->end - intvl->start + 1) / MAX_FRAG_LEN + 1;
                intvl->end = intvl->start + MAX_FRAG_LEN * recordnum - 1;
                printf("change range to [%u, %u]\n", intvl->start, intvl->end);
                recved_seq.printIntervals();
            }
#endif
        return 0;
    }
    else
        return -1;
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
            // printf("get_tcp_seq: Not full divide: seq(%u %x) mod record_full_size(%d)\n", byte_seq, byte_seq, MAX_FRAG_LEN);
            log_info("get_tcp_seq: Not full divide: seq(%u %x) mod record_full_size(%d)\n", byte_seq, byte_seq, MAX_FRAG_LEN);
        }
        byte_seq += (byte_seq) / MAX_FRAG_LEN * (TLSHDR_SIZE + 8 + 16);
    }
#endif

    return byte_seq;
}




int Optimack::send_http_range_request(void* sockfd, Interval range){
    uint start = range.start, end = range.end;
    if (start == end || (start == 0 || end == 0))
        return -1;
    
    char range_request[MAX_RANGE_REQ_LEN];
    memcpy(range_request, request, request_len);
    sprintf(range_request+request_len-2, "Range: bytes=%u-%u\r\n\r\n", start, end);

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
    }
    
    if (rv < 0){
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
        printf("[Range] bytes [%u, %u] requested, No.%d\n", start, end, range_request_count);
        log_debug("[Range] bytes %d - %d requested, No.%d", start, end, range_request_count);
        return 0;
    }
}


void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    close(range_sockfd);
    range_sockfd_old = range_sockfd;
    range_sockfd = -1;
    memset(header, 0, sizeof(http_header));
    consumed = unread = parsed = recv_offset = unsent = 0;
}

int Optimack::get_http_response_header_len(subconn_info* subconn, unsigned char* payload, int payload_len){
    Http1::ResponseParser rp;
    SBuf headerBuf;
    pthread_mutex_lock(&mutex_range);
    headerBuf.assign((char*)payload, payload_len);
    rp.parse(headerBuf);
    response_header_len = rp.messageHeaderSize();
    pthread_mutex_unlock(&mutex_range);

    // response_header_len = 398;
    response = (char*)malloc(response_header_len+1);
    memcpy(response, payload, response_header_len);
    response[response_header_len] = 0;

    const char* content_len_field = "Content-Length: ";
    int content_len_field_len = strlen(content_len_field);
    char* p_content_len = std::search((char*)payload, (char*)payload+payload_len, content_len_field, content_len_field+content_len_field_len);
    p_content_len += content_len_field_len;
    file_size = (u_int)strtol(p_content_len, &p_content_len, 10);
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
    printf("S%d-%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn->id, subconn->local_port, response_header_len, rp.parseStatusCode, file_size, ack_end);
    log_info("S%d-%d: Server response - headBlockSize %u, StatusCode %d, ContentLength %u, ACK end %u\n", subconn->id, subconn->local_port, response_header_len, rp.parseStatusCode, file_size, ack_end);
    // printf("seq in this conn-%u, file byte-%u, %c\n", seq_rel+response_header_len, 0, payload[response_header_len+1]);
    // src/http/StatusCode.h
}

