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
#include <openssl/ssl.h>

#include <map>
#include <utility>
#include <iterator>
#include <functional>
#include <algorithm>
#include <cstdlib>
#include <string>
#include <sstream>

#include<sys/socket.h>
#include <netdb.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include "logging.h"
#include "util.h"
#include "hping2.h"
#include "socket.h"
#include "thr_pool.h"

#include "get_server_key_single.h"

//Original 
#define LOGSIZE 10240
int nfq_stop;
thr_pool_t* pool;
char local_ip[16];
char remote_ip[16];
unsigned short local_port;
unsigned short remote_port = 443;
char *remote_domain;

struct thread_data {
    unsigned int  pkt_id;
    unsigned int  len;
    unsigned char *buf;
};

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data);
void* nfq_loop(void *arg);
void* pool_handler(void* arg);
int process_tcp_packet(struct thread_data* thr_data);


#define NF_QUEUE_NUM 6
struct nfq_handle *g_nfq_h;
struct nfq_q_handle *g_nfq_qh;
int g_nfq_fd;

int setup_nfq()
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        log_error("error during nfq_open()");
        return -1;
    }

    log_debug("unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_unbind_pf()");
        return -1;
    }

    log_debug("binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    log_debug("binding this socket to queue %d", NF_QUEUE_NUM);
    g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, NULL);
    if (!g_nfq_qh) {
        log_error("error during nfq_create_queue()");
        return -1;
    }
    log_debug("nfq queue handler: %p", g_nfq_qh);

    log_debug("setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        log_error("can't set packet_copy mode");
        return -1;
    }

#define NFQLENGTH 1024*200
#define BUFLENGTH 4096
    if (nfq_set_queue_maxlen(g_nfq_qh, NFQLENGTH) < 0) {
        log_error("error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    nfnl_rcvbufsiz(nfnl_hl, NFQLENGTH * BUFLENGTH);

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int teardown_nfq()
{
    log_debug("unbinding from queue %d", NF_QUEUE_NUM);
    if (nfq_destroy_queue(g_nfq_qh) != 0) {
        log_error("error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    log_debug("unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    log_debug("closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        log_error("error during nfq_close()");
        return -1;
    }

    return 0;
}

void signal_handler(int signum)
{
    log_debug("Signal %d recved.", signum);
    if(signum == SIGPIPE){
        log_exp("Receive EPIPE.");
        return;
    }
    nfq_stop = 1;
    teardown_nfq();
    // cleanup();
    exit(EXIT_FAILURE);
}

const int MARK = 66;
// int sockraw, sockpacket;

void init()
{
    // init random seed
    srand(time(NULL));

    init_log();

    // initializing globals
    sockraw = open_sockraw();
    if (setsockopt(sockraw, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK)) < 0)
    {
        log_error("couldn't set mark\n");
        exit(1);
    }

    // int portno = 80;
    // sockpacket = open_sockpacket(portno);
    // if (sockpacket == -1) {
    //     log_error("[main] can't open packet socket\n");
    //     exit(EXIT_FAILURE);
    // }

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        log_error("register SIGINT handler failed.\n");
        exit(EXIT_FAILURE);
    }
    if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        log_error("register SIGSEGV handler failed.");
        exit(EXIT_FAILURE);
    }
    if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        log_error("register SIGPIPE handler failed.");
        exit(EXIT_FAILURE);
    }

    if (setup_nfq() == -1) {
        log_error("unable to setup netfilter_queue");
        exit(EXIT_FAILURE);
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    struct thread_data* thr_data = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (!thr_data)
    {
            log_error("cb: error during thr_data malloc\n");
            return -1;                                /* code */
    }
    memset(thr_data, 0, sizeof(struct thread_data));
    // log_exp("cb: id %d, protocol 0x%04x", ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id), nfq_get_msg_packet_hdr(nfa)->hw_protocol);
    thr_data->pkt_id = htonl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len);
    if (!thr_data->buf){
            log_error("cb: error during malloc\n");
            return -1;
    }
    memcpy(thr_data->buf, packet, packet_len);

    pool_handler(thr_data);
    // if(thr_pool_queue(pool, pool_handler, (void *)thr_data) < 0){
    //         log_error("cb: error during thr_pool_queue\n");
    //         return -1;
    // }

    return 0;
}

void* pool_handler(void* arg){
    struct thread_data* thr_data = (struct thread_data*)arg;
    u_int32_t id = thr_data->pkt_id;
    int ret = -1;

    // log_exp("pool_handler: %d", id);
    short protocol = ip_hdr(thr_data->buf)->protocol;
    if (protocol == 6)
        ret = process_tcp_packet(thr_data);
    else{ 
        log_error("Invalid protocol: 0x%04x, len %d", protocol, thr_data->len);
    }

    // free(thr_data->buf);
    free(thr_data);

    if (ret == 0){
        nfq_set_verdict(g_nfq_qh, id, NF_ACCEPT, 0, NULL);
        // log_exp("verdict: accpet\n");
    }
    else{
        nfq_set_verdict(g_nfq_qh, id, NF_DROP, 0, NULL);
        // log_exp("verdict: drop\n");
    }
}

struct record_fragment{
    // bool is_header;
    unsigned char* data;//whole record, header and data
    int data_len;
    record_fragment( unsigned char* dt, int dl){
        data = dt; data_len = dl;
    }
};

class TLS_rcvbuf{
public:
    TLS_rcvbuf() { tls_ciphertext_rcvbuf.clear(); }
    int insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len);
    int merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);
    int merge_record_fragment();
    int decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int decrypt_whole_record(unsigned char* record_data, int record_len, unsigned char* plaintext, unsigned char* add);
    int generate_record(uint seq, unsigned char* plaintext, int len, unsigned char* record_buf);

    void set_credentials(const EVP_CIPHER * ec, unsigned char* salt, unsigned char* key, int rs){
        this->evp_cipher = ec;
        
        memcpy(this->iv_salt, salt, 4);
        this->iv_salt[4] = 0;

        memcpy(this->write_key_buffer, key, 100);//100 to be modified
        this->write_key_buffer[99] = 0;

        this->record_size = rs;
        this->record_full_size = TLSHDR_SIZE + 8 + rs + 16;

        this->key_obtained = true;
    }

    bool get_key_obtained() {
        return this->key_obtained;
    }

    uint get_seq_data_start() {
        return this->seq_data_start;
    }

    void set_seq_data_start(uint sds){
        this->seq_data_start = sds;
    }

    void set_iv_explicit_init(unsigned char* iv_ex){
        memcpy(this->iv_xplct_ini, iv_ex, 8);
        this->iv_xplct_ini[8] = 0;
    }

    void lock(){
        pthread_mutex_lock(&mutex);
    }

    void unlock(){
        pthread_mutex_unlock(&mutex);
    }

    // std::map<uint, struct record_fragment> tls_plaintext_rcvbuf;

private:
    int insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint seq, unsigned char* ciphertext, int ciphertext_len);

    bool key_obtained = false;
    const EVP_CIPHER *evp_cipher;
    unsigned char iv_salt[5], iv_xplct_ini[9]; // 4 to be modified
    unsigned char write_key_buffer[100]; // 100 to be modified
    uint seq_data_start = 0;
    int record_size = 0, record_full_size = 0;
    std::map<uint, struct record_fragment, std::less<uint>> tls_ciphertext_rcvbuf;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
};

TLS_rcvbuf tls_rcvbuf;

int print_hexdump(unsigned char* hexdump, int len){
    for(int i = 0; i < len; i++){
        printf("%02x ", hexdump[i]);
        if(i % 16 == 15)
            printf("\n");
    }
    printf("\n\n");
}

int TLS_rcvbuf::decrypt_whole_record(unsigned char* record_data, int record_len, unsigned char* plaintext, unsigned char* aad){
    if(record_len <= 8)
        return -1;

    unsigned char iv[13];
    memcpy(iv, iv_salt, 4);
    memcpy(iv+4, record_data, 8);
    iv[12] = 0;
    printf("IV: ");
    for(int i = 0; i < 12; i++)
        printf("%02x", iv[i]);
    printf("\n");

    // unsigned char plaintext[20000] = {0};
    int ret = gcm_decrypt(record_data+8, record_len-8-16, evp_cipher, aad, 9, write_key_buffer, iv, 12, plaintext, record_data+record_len-16);
    plaintext[record_len-8-16] = 0;
    printf("Plaintext: len %d\n\n", ret);
    // printf("Plaintext: len %d\n%s\n\n", ret, plaintext);
    // print_hexdump(plaintext, record_len-8-16);
    
    // unsigned char re_ciphertext[2000];
    // unsigned char re_tag[17];
    // ret = gcm_encrypt(plaintext, record_len-8-16, evp_cipher, write_key_buffer, iv, 12, re_ciphertext, re_tag);
    // re_tag[16] = 0;

    // printf("Re encrypted: %d\n", ret);
    // for(int i = 0; i < record_len-8-16; i++){
    //     printf("%02x", record_data[i+8]);
    //     printf("%02x ", re_ciphertext[i]);
    //     if(i % 16 == 15)
    //         printf("\n");
    // }
    // printf("\n\n");

    // printf("Original tag: ");
    // for(int i = 0; i < 16; i++)
    //     printf("%02x ", record_data[record_len-16+i]);
    // printf("\n");

    // printf("Reencryp tag: ");
    // for(int i = 0; i < 16; i++)
    //     printf("%02x ", re_tag[i]);
    // printf("\n");

    // ret = gcm_decrypt(record_data+8, record_len-8-16, evp_cipher, write_key_buffer, iv, 12, plaintext, re_tag);
    // plaintext[record_len-8-16] = 0;
    // printf("Plaintext: len %d\n%s\n\n", ret, plaintext);
    return record_len-8-16;
}

int TLS_rcvbuf::generate_record(uint seq, unsigned char* plaintext, int len, unsigned char* record_buf){
    //len > record_size?
    
    int record_len = TLSHDR_SIZE+8+len+16;
    // record_buf = (unsigned char*)malloc(record_len+1);
    // if(!record_buf){
    //     printf("generate_record:335: malloc(%d) failed!\n", record_len);
    //     return -1;
    // }
    struct mytlshdr* tlshdr = (struct mytlshdr*)record_buf;
    tlshdr->version = 0x0303;
    tlshdr->type = TLS_TYPE_APPLICATION_DATA;
    tlshdr->length = htons(8+len+16);

    unsigned char iv[13];
    int num_record = (seq - seq_data_start) / record_full_size;
    if( (seq - seq_data_start) % record_full_size != 0){
        printf("generate_record: seq(%u) - seq_data_start(%u) mod record_full_size(%d) != 0\n", seq, seq_data_start, record_full_size);
    }
    memcpy(iv, iv_salt, 4);
    unsigned long long iv_num = htobe64(*((unsigned long long*)iv_xplct_ini));
    iv_num = htobe64(iv_num+num_record);
    memcpy(iv+4, &iv_num, 8);
    iv[12] = 0;
    printf("iv_xplct_ini: ");
    hex_dump(iv_xplct_ini, 8);
    printf("iv_explct: + %d", num_record);
    hex_dump(iv+4, 8);
    memcpy(record_buf+TLSHDR_SIZE, iv+4, 8);
    
    int ret = gcm_encrypt(plaintext, len, evp_cipher, write_key_buffer, iv, 12, record_buf+TLSHDR_SIZE+8, record_buf+record_len-16);
    
    record_buf[record_len] = 0;
    return record_len;
}



unsigned char* merge_two_data(unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len){
    unsigned char* new_data = (unsigned char*)malloc(first_data_len+second_data_len);
    if(!new_data){
        printf("merge_two_data:370: malloc(%d) failed!\n", first_data_len+second_data_len);
        return first_data;
    }
    memcpy(new_data, first_data, first_data_len);
    memcpy(new_data+first_data_len, second_data, second_data_len);
    free(first_data);
    free(second_data);
    return new_data;
}

int TLS_rcvbuf::merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len){
    frag->data = merge_two_data(first_data, first_data_len, second_data, second_data_len);
    frag->data_len = first_data_len + second_data_len;
    return 0;
}


int TLS_rcvbuf::merge_record_fragment(){
    if(tls_ciphertext_rcvbuf.empty())
        return -1;
    for(auto prev = tls_ciphertext_rcvbuf.begin(), cur=std::next(prev); prev != tls_ciphertext_rcvbuf.end();){
        int prev_len = prev->second.data_len, cur_len = cur->second.data_len;

        if(prev->first + prev_len == cur->first){
            printf("merge_record_fragment: %u-(%p, %d) and %u-(%p, %d)\n", prev->first, prev->second.data, prev->second.data_len, cur->first, cur->second.data, cur->second.data_len);
            merge_two_record_fragment(&prev->second, prev->second.data, prev->second.data_len, cur->second.data, cur->second.data_len);
            tls_ciphertext_rcvbuf.erase(cur++);
            continue;
        }
        prev=cur;
        cur++;
    }
    return 0;
}

int TLS_rcvbuf::decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    int decrypt_start_local = ((seq-seq_data_start)/record_full_size)*record_full_size+seq_data_start - seq;
    int decrypt_end_local;
    if(decrypt_start_local < 0){
        printf("decrypt_record_fragment: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d)\n", decrypt_start, seq_data_start, seq, payload, payload_len);
        decrypt_start_local += record_full_size;
        // exit(-1);
    }

    for(decrypt_end_local = decrypt_start_local; decrypt_end_local+record_full_size <= payload_len; decrypt_end_local += record_full_size){
        struct mytlshdr* tlshdr = (struct mytlshdr*)(payload+decrypt_end_local);
        int tlshdr_len = htons(tlshdr->length);
        printf("\nTLS Record: version %x, type %d, len %d(%x), offset %d\n", tlshdr->version, tlshdr->type, tlshdr_len, tlshdr_len, decrypt_end_local);

        if(!( (tlshdr->version == 0x0303 || tlshdr->version == 0x0304) && tlshdr->type == TLS_TYPE_APPLICATION_DATA ) ){
            printf("decrypt_record_fragment: header not found\n\n");
            printf("After:\n");
            print_hexdump(payload, payload_len);
            printf("New header: \n");
            print_hexdump(payload+decrypt_end_local, payload_len-decrypt_end_local);
            exit(-1);
        }
        else {
            if(tlshdr_len != record_full_size-TLSHDR_SIZE){
                printf("tlshdr length %d != %lu !\n", tlshdr_len, record_full_size-TLSHDR_SIZE);
            }
            unsigned char* plaintext = new unsigned char[record_full_size-TLSHDR_SIZE+1];
            unsigned char aad[10];
            uint seq_tmp = seq+decrypt_end_local;
            memcpy(aad, &seq_tmp, 4);
            memcpy(aad+4, payload+decrypt_end_local, 5);
            int plaintext_len = decrypt_whole_record(payload+decrypt_end_local+TLSHDR_SIZE, tlshdr_len, plaintext, aad);
            insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, plaintext, plaintext_len);

            // unsigned char* ciphertext = new unsigned char[record_full_size+1];
            // int ciphertext_len;
            // ciphertext_len = generate_record(it->first+decrypt_end_local, plaintext, tlshdr_len-8-16, ciphertext, ciphertext_len);
            
            // printf("Re encrypted: %d\n", ciphertext_len);
            // for(int i = 0; i < ciphertext_len; i++){
            //     printf("%02x", *(it->second.data+decrypt_end_local+i));
            //     printf("%02x ", ciphertext[i]);
            //     if(i % 16 == 15)
            //         printf("\n");
            // }
            // printf("\n\n");

            delete plaintext;
            // delete ciphertext;
            //How to erase decrypted one?
        }
    }
    decrypt_start = decrypt_start_local;
    decrypt_end = decrypt_end_local;
    return 0;
}

int TLS_rcvbuf::decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    //Use seq to find the header
    for(auto it = tls_ciphertext_rcvbuf.begin(); it != tls_ciphertext_rcvbuf.end();){
        int decrypt_start, decrypt_end;
        decrypt_one_payload(it->first, it->second.data, it->second.data_len, decrypt_start, decrypt_end, plaintext_rcvbuf);

        if(decrypt_end != decrypt_start){
            if(decrypt_end < it->second.data_len)
                insert_to_record_fragment(it->first+decrypt_end, it->second.data+decrypt_end, it->second.data_len-decrypt_end);
            if(decrypt_start){
                unsigned char* old_data = it->second.data;
                unsigned char* new_data = (unsigned char*)malloc(decrypt_start);
                memcpy(new_data, old_data, decrypt_start);
                it->second.data = new_data;
                it->second.data_len = decrypt_start;
                free(old_data);
            }
            else {
                free(it->second.data);
                tls_ciphertext_rcvbuf.erase(it++);
                continue;
            }
        }
        it++;
    }
}

int TLS_rcvbuf::insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len){
    return insert_to_rcvbuf(tls_ciphertext_rcvbuf, seq, ciphertext, ciphertext_len);
}


int TLS_rcvbuf::insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint new_seq_start, unsigned char* new_data, int new_data_len){
    unsigned char* temp_buf = (unsigned char*)malloc(new_data_len);
    if(!temp_buf){
        log_error("insert_to_recv_buffer: can't malloc for data_left");
        return -1;
    }
    memset(temp_buf, 0, new_data_len);
    memcpy(temp_buf, new_data, new_data_len);

    auto ret = tls_rcvbuf.insert( std::pair<uint , struct record_fragment>(new_seq_start, record_fragment(temp_buf, new_data_len)) );
    if (ret.second == false) {
        printf("tls_ciphertext_rcvbuf: %u already existed.\n", new_seq_start);
        if(ret.first->second.data_len < new_data_len){
            // printf("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            // log_error("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            free(ret.first->second.data);
            ret.first->second.data = NULL;
            ret.first->second.data = temp_buf;
            ret.first->second.data_len = new_data_len;
        }
        else
            return -1;
    }
    printf("insert_to_record_fragment: %u-(%p, %d) inserted\n", new_seq_start, temp_buf, new_data_len);
    // merge_record_fragment(tls_ciphertext_rcvbuf);
    return 0;
}

// int insert_and_merge_to_record_fragment(){
        // uint new_seq_end = new_seq_start + new_data_len;
    // for(auto it = tls_ciphertext_rcvbuf.begin(); it != tls_ciphertext_rcvbuf.end();it++){
    //         uint cur_seq_start = it->first;
    //         uint cur_seq_end = it->first+it->second.data_len;
    //         if(cur_seq_end < new_seq_start)
    //             continue;
    //         if(new_seq_end < cur_seq_start || (new_seq_start <= cur_seq_end && cur_seq_end < new_seq_end)){// insert before it
    //             unsigned char* temp_buf = (unsigned char*)malloc(new_data_len);
    //             if(!temp_buf){
    //                 log_error("insert_to_recv_buffer: can't malloc for data_left");
    //                 return -1;
    //             }
    //             memset(temp_buf, 0, new_data_len);
    //             memcpy(temp_buf, new_data, new_data_len);

    //             auto ret = tls_ciphertext_rcvbuf.insert( std::pair<uint , struct record_fragment>(seq, record_fragment(is_header, temp_buf, ciphertext_len)) );
    //             if(new_seq_start <= cur_seq_end && cur_seq_end < new_seq_end)
    //                 tls_ciphertext_rcvbuf.erase(it++);
    //             break;
    //         }

    //         if(new_seq_start <= cur_seq_end && cur_seq_end < new_seq_end) { // [new_seq_start <= cur_seq_end] < new_seq_end, merge
    //             merge_two_record_fragment(&it->second, it->second.data, it->second.data_len, new_data-new_seq_start+cur_seq_end, new_seq_end-cur_seq_end);
    //             continue;
    //         }
            
    //         if(cur_seq_start <= new_seq_start && new_seq_end <= cur_seq_end) { // cur_seq_start <= [new_seq_start < new_seq_end <= cur_seq_end], contain, break
    //             break;
    //         }
    //         else if(new_seq_start <  cur_seq_start < new_seq_end){ //[new_seq_start < cur_seq_start] < [new_seq_end < cur_seq_end]

    //         }
    //         else if(seq+ciphertext_len >= it->first){ //it->first+it->second.data_len > seq, overlap, merge 
    //             merge_two_record_fragment(&it->second, ciphertext, it->first-seq, it->second.data, it->second.data_len);
    //         else { //it->first+it->second.data_len > seq, insert before it
                
    //         }
            
    // }
// }

int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){
    bool is_valid = true;
    tls_rcvbuf.lock();
    if(!tls_rcvbuf.get_key_obtained()){
        is_valid = false;
    }
    else if(!tls_rcvbuf.get_seq_data_start()){
        if(contains_header){
            tls_rcvbuf.set_seq_data_start(seq);
            tls_rcvbuf.set_iv_explicit_init(payload+TLSHDR_SIZE);
        }
        else
            is_valid = false;
    }
    tls_rcvbuf.unlock();
    if(!is_valid)
        return 0;


    int decrypt_start = 0, decrypt_end = 0;
    tls_rcvbuf.decrypt_one_payload(seq, payload, payload_len, decrypt_start, decrypt_end, plaintext_buf_local);

    if(decrypt_end != decrypt_start){
        tls_rcvbuf.lock();
        if(decrypt_end < payload_len)
            tls_rcvbuf.insert_to_record_fragment(seq+decrypt_end, payload+decrypt_end, payload_len-decrypt_end);
        if(decrypt_start){
            tls_rcvbuf.insert_to_record_fragment(seq, payload, decrypt_start);
        }
        tls_rcvbuf.merge_record_fragment();
        tls_rcvbuf.decrypt_record_fragment(plaintext_buf_local);
        tls_rcvbuf.unlock();
    }
    return 1;
}


//return verdict
int process_tls_payload(bool in_coming, unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){
    int read_bytes = 0;
    while(read_bytes < payload_len){
        unsigned char* remain_payload = payload+read_bytes;
        struct mytlshdr *tlshdr = (struct mytlshdr*)(remain_payload);
        int tlshdr_len = htons(tlshdr->length);

        if(tlshdr->version == 0x0303 || tlshdr->version == 0x0304){
            // unsigned char* ciphertext = remain_payload + TLSHDR_SIZE;
            // int ciphertext_len = (tlshdr_len < payload_len - read_bytes - TLSHDR_SIZE)? tlshdr_len : payload_len - read_bytes - TLSHDR_SIZE;
            printf("process_tcp_packet: TLS Record: version %x, type %d, len %d(%x)\n", tlshdr->version, tlshdr->type, tlshdr_len, tlshdr_len);
            switch (tlshdr->type){
                case TLS_TYPE_HANDSHAKE:
                case TLS_TYPE_CHANGE_CIPHER_SPEC:// what if an application data comes after 
                {
                    return 0;
                    break;
                }
                case TLS_TYPE_APPLICATION_DATA:
                {
                    if(in_coming){
                        if(tlshdr_len > 8){
                            // Assumption: application data followed by application data
                            // insert the rest of the packet to rcvbuf, might contain two or more record
                            return process_incoming_tls_appdata(true, seq+read_bytes, payload+read_bytes, payload_len-read_bytes, tls_rcvbuf, plaintext_buf_local);
                            
                        }
                    }
                    else 
                        return 0;
                    break;
                }
                default:
                    printf("Unknown type: %d letting through\n", tlshdr->type);
                    return 0;
                    break;
            }
            read_bytes += tlshdr_len + TLSHDR_SIZE;
        }
        else{
            if(in_coming){
                printf("TLS: fragment\n");
                return process_incoming_tls_appdata(false, seq+read_bytes, payload+read_bytes, payload_len-read_bytes, tls_rcvbuf, plaintext_buf_local);
            }
            else
                return 0;
            break;
        }
    }

}


int process_tcp_packet(struct thread_data* thr_data)
{
    char log[LOGSIZE], time_str[64];

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *tcp_opt = tcp_options(thr_data->buf);
    unsigned int tcp_opt_len = tcphdr->th_off*4 - TCPHDR_SIZE;
    unsigned char *payload = tcp_payload(thr_data->buf);
    int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    printf("P%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d\n", thr_data->pkt_id, remote_ip, sport, local_ip, dport, tcp_flags_str(tcphdr->th_flags), seq, seq, ack, ack, iphdr->ttl, payload_len);
    // return 0;
    if(payload_len){
        std::map<uint, struct record_fragment> plaintext_buf_local;
        int verdict = process_tls_payload(sport == 443, seq, ack, payload, payload_len, tls_rcvbuf, plaintext_buf_local);
        if(verdict == 0)
            return 0;
        else if(verdict == -1)
            return 1;
        
        printf("Payload:\n");
        hex_dump(payload, payload_len);
        for(auto it = plaintext_buf_local.begin(); it != plaintext_buf_local.end();){
            unsigned char* ciphertext = new unsigned char[541+1];
            int ciphertext_len = tls_rcvbuf.generate_record(it->first, it->second.data, it->second.data_len, ciphertext);
            memcpy(ciphertext+ciphertext_len-16, payload+payload_len-16, 16);
            send_ACK_payload(local_ip, remote_ip, dport, sport, ciphertext, ciphertext_len, ack, it->first);
            printf("Reencrypt:\n");
            hex_dump(ciphertext, ciphertext_len);
            delete ciphertext;
            plaintext_buf_local.erase(it++);
        }
    }

    return 1;
}

void *nfq_loop(void *arg)
{
    int rv;
    char buf[65536];

    while (!nfq_stop) {
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            //log_debug("%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(g_nfq_h, buf, rv);
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_debug("recv() ret %d errno: %d", rv, errno);
            }
            usleep(10); //10000
        }
    }
}

int RecvPacket(SSL *ssl)
{
    int len=100;
    char buf[4001];
    do {
        len=SSL_read(ssl, buf, 4000);
        buf[len]=0;
        printf("Received: len = %d\n%s\n\n", len, buf);
//        fprintf(fp, "%s",buf);
    } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ){
            printf("SSL_read_error: SSL_ERROR_WANT_READ\n");
            return 0;
        }
        if (err == SSL_ERROR_WANT_WRITE){
            printf("SSL_read_error: SSL_ERROR_WANT_WRITE\n");
            return 0;
        }
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL){
            printf("SSL_read_error: %d\n", err);
            return -1;
        }
    }
}


int open_ssl_conn(int fd){
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    // const SSL_METHOD *method = TLSv1_2_client_method(); /* Create new client-method instance */
    
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("SSL_CTX_new() failed\n");
        return -1;
    }
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    SSL_CTX_set_tlsext_max_fragment_length(ctx, TLSEXT_max_fragment_length_512);
    SSL_CTX_set_max_send_fragment(ctx, 512);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("SSL_new() failed\n");
        return -1;
    }
    SSL_set_tlsext_max_fragment_length(ssl, TLSEXT_max_fragment_length_512);
    SSL_set_fd(ssl, fd);
    // const char* const PREFERRED_CIPHERS = "TLS_AES_128_GCM_SHA256";
    const char* const PREFERRED_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256"; // Use TLS 1.2 GCM hardcoded.
    
    // SSL_CTX_set_ciphersuites(ctx, PREFERRED_CIPHERS);
    SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS);

    // SSL_set_ciphersuites(ssl, PREFERRED_CIPHERS);
    const int status = SSL_connect(ssl);
    if (status != 1)
    {
        SSL_get_error(ssl, status);
        printf("SSL_connect failed with SSL_get_error code %d\n", status);
        return -1;
    }
    STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        printf("%s\n",SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    }
    printf("\n");
    printf("Connected with %s encryption, max_frag_len %d\n", SSL_get_cipher(ssl),SSL_SESSION_get_max_fragment_length(ssl->session));
    
    char request[400];
    sprintf(request, "GET /ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    SSL_write(ssl, request, strlen(request));
    printf("Write: %s\n\n", request);

    unsigned char write_key_buffer[100],iv_salt[5];
    // get_server_session_key_and_iv_salt(ssl, session_key, iv_salt);
    
    unsigned char master_key[100];
    unsigned char client_random[100];
    unsigned char server_random[100];
    size_t master_key_len = SSL_SESSION_get_master_key(SSL_get_session(ssl), master_key, sizeof(master_key));
    printf("master_key_len: %ld\n", master_key_len);
    size_t client_random_len = SSL_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE);
    printf("client_random_len: %ld\n", client_random_len);
    size_t server_random_len = SSL_get_server_random(ssl, server_random, SSL3_RANDOM_SIZE);
    printf("server_random_len: %ld\n", server_random_len);
    const EVP_MD *digest_algorithm = SSL_CIPHER_get_handshake_digest(SSL_SESSION_get0_cipher(SSL_get_session(ssl)));
    const SSL_CIPHER *cipher = SSL_SESSION_get0_cipher(SSL_get_session(ssl));
    printf("current session cipher name: %s\n", SSL_CIPHER_standard_name(cipher));
    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname("AES-128-GCM"); // Temporary Ugly hack here for Baidu.
    printf("evp_cipher: %p\n", evp_cipher);
    ssize_t key_length = EVP_CIPHER_key_length(evp_cipher);
    printf("key_length: %ld\n", key_length);

    test_write_key(ssl, digest_algorithm, evp_cipher, iv_salt, write_key_buffer);
    printf("iv_salt: ");
    for(int i = 0; i < 4; i++)
        printf("%02x", iv_salt[i]);
    printf("\n");

    tls_rcvbuf.set_credentials(evp_cipher, iv_salt, write_key_buffer, 512);

    RecvPacket(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}

int establish_tcp_connection()
{
    int sockfd;
    struct sockaddr_in server_addr;

    // Open socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Can't open stream socket.");
        return -1;
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_ip);
    server_addr.sin_port = htons(remote_port);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        close(sockfd);
    }

    return sockfd;
}

int get_localport(int fd){
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

int hostname_to_ip(char *hostname , char *ip)
{
	int sockfd;  
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *h;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;

	if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0) 
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		h = (struct sockaddr_in *) p->ai_addr;
		strcpy(ip , inet_ntoa( h->sin_addr ) );
	}
	
	freeaddrinfo(servinfo); // all done with this structure
    printf("%s resolved to %s\n" , hostname , ip);
	return 0;
}

int main(int argc, char *argv[])
{
    int opt;

    if (argc < 1) {
        printf("Usage: %s <domain> \n", argv[0]);
        exit(-1);
    }

    remote_domain =  argv[1];
    hostname_to_ip(remote_domain, remote_ip);
    // resolve((struct sockaddr*)&remote, remote_ip);

    strncpy(local_ip, "165.22.184.181", 16);
    // remote_port = atoi(argv[2]);
    // local_port = atoi(argv[3]);

    // strncpy(remote_host_name, argv[4], 63);
    // strncpy(local_host_name, argv[5], 63);


    /* records are saved in folder results */
    /* create the directory if not exist */
    // char hostname_pair_path[64], result_path[64];
    // mkdir("results", 0755);

    // time_t rawtime;
    // struct tm * timeinfo;
    // char time_str[20];
    // char tmp[64];

    // sprintf(hostname_pair_path, "results/%s-%s", local_ip, remote_ip);
    // mkdir(hostname_pair_path, 0755);

    // time(&rawtime);
    // timeinfo = localtime(&rawtime);
    // strftime(time_str, 20, "%Y%m%d_%H%M%S", timeinfo);
    // sprintf(result_path, "%s/%s", hostname_pair_path, time_str);
    // mkdir(result_path, 0755);

    init();

    // start the nfq proxy thread
    nfq_stop = 0;
    pthread_t nfq_thread;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, NULL) != 0){
        log_error("Fail to create nfq thread.");
        exit(EXIT_FAILURE);
    }
    printf("created nfq thread\n");

    int sockfd = establish_tcp_connection();
    local_port = get_localport(sockfd);
    // local_port = 36000;
    printf("Local IP: %s\n", local_ip);
    printf("Local Port: %d\n", local_port);
    printf("Remote IP: %s\n", remote_ip);
    printf("Remote Port: %d\n", remote_port);

    char* cmd = (char*) malloc(200);
    sprintf(cmd, "iptables -A INPUT -p tcp -s %s --sport %d --dport %d -m mark --mark %d -j ACCEPT", remote_ip, remote_port, local_port, MARK);
    system(cmd);

    sprintf(cmd, "iptables -A INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);

    sprintf(cmd, "iptables -A OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);

    printf("Before calling open_ssl_conn()\n");
    // while(true);
    open_ssl_conn(sockfd);
    while(1);
    printf("After calling open_ssl_conn()\n");

    // cleanup();
    teardown_nfq();

    sprintf(cmd, "iptables -D INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);

    sprintf(cmd, "iptables -D OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);
}