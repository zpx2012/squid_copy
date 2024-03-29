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

#include<sys/socket.h>
#include <netdb.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include "logging.h"
#include "util.h"
#include "hping2.h"
// #include "socket.h"
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

unsigned char iv_salt[4]; // 4 to be modified
unsigned char write_key_buffer[100]; // 100 to be modified


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


unsigned char ciphertext_buf[4000] = {0};
bool key_obtained = false;
int consumed = 0;
const EVP_CIPHER *evp_cipher;
uint seq_ini_rem = 0;

struct record_fragment{
    int record_size;
    unsigned char* data;
    int data_len;
    record_fragment(int rs, unsigned char* dt, int dl){
        record_size = rs; data = dt; data_len = dl;
    }
};
std::map<uint, struct record_fragment, std::less<uint>> tls_ciphertext_rcvbuf;

int decrypt_whole_record(unsigned char* record_data, int record_len){
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

    unsigned char plaintext[20000] = {0};
    int ret = gcm_decrypt(record_data+8, record_len-8-16, evp_cipher, write_key_buffer, iv, 12, plaintext, record_data+record_len-16);
    plaintext[record_len-8-16] = 0;
    printf("Plaintext: len %d\n%s\n\n", ret, plaintext);
    
    unsigned char re_ciphertext[2000];
    unsigned char re_tag[17];
    ret = gcm_encrypt(plaintext, record_len-8-16, evp_cipher, write_key_buffer, iv, 12, re_ciphertext, re_tag);
    re_tag[16] = 0;

    printf("Re encrypted: %d\n", ret);
    for(int i = 0; i < record_len-8-16; i++){
        printf("%02x", record_data[i+8]);
        printf("%02x ", re_ciphertext[i]);
        if(i % 16 == 15)
            printf("\n");
    }
    printf("\n\n");

    printf("Original tag: ");
    for(int i = 0; i < 16; i++)
        printf("%02x ", record_data[record_len-16+i]);
    printf("\n");

    printf("Reencryp tag: ");
    for(int i = 0; i < 16; i++)
        printf("%02x ", re_tag[i]);
    printf("\n");

    ret = gcm_decrypt(record_data+8, record_len-8-16, evp_cipher, write_key_buffer, iv, 12, plaintext, re_tag);
    plaintext[record_len-8-16] = 0;
    printf("Plaintext: len %d\n%s\n\n", ret, plaintext);
    return 0;
}
int insert_to_record_fragment(std::map<uint, struct record_fragment> &tls_ciphertext_rcvbuf, uint seq, int record_size, unsigned char* ciphertext, int ciphertext_len);

int print_hexdump(unsigned char* hexdump, int len){
    for(int i = 0; i < len; i++){
        printf("%02X ", hexdump[i]);
        if(i % 16 == 4)
            printf("\n");
    }
    printf("\n\n");
}

int merge_record_fragment(std::map<uint, struct record_fragment> &tls_ciphertext_rcvbuf){
    for(auto prev = tls_ciphertext_rcvbuf.begin(), cur=std::next(prev); prev != tls_ciphertext_rcvbuf.end();){
        int prev_len = prev->second.data_len, cur_len = cur->second.data_len;

        if(prev->first + prev_len == cur->first){
            printf("merge_record_fragment: %u-(%d, %p, %d) and %u-(%d, %p, %d)\n", prev->first, prev->second.record_size, prev->second.data, prev->second.data_len, cur->first, cur->second.record_size, cur->second.data, cur->second.data_len);
            if(prev->second.record_size && prev->second.record_size < prev_len+cur_len){ //new record in middle of fragment, motherfucker
                int len_last_record = prev->second.record_size - prev->second.data_len;
                int len_new_record = cur->second.data_len - len_last_record;

                if(len_new_record >= TLSHDR_SIZE){
                    printf("Before:\n");
                    print_hexdump(cur->second.data, cur->second.data_len);
                    struct mytlshdr* tlshdr = (struct mytlshdr*)(cur->second.data+len_last_record);
                    printf("TLS Record: version %x, type %d, len %d(%x)\n\n", tlshdr->version, tlshdr->type, htons(tlshdr->length), tlshdr->length);

                    if((tlshdr->version == 0x0303 || tlshdr->version == 0x0304) && tlshdr->type == TLS_TYPE_APPLICATION_DATA){
                        tlshdr->length = htons(tlshdr->length);
                        unsigned char* ciphertext = cur->second.data + len_last_record + TLSHDR_SIZE;
                        int ciphertext_len = len_new_record - TLSHDR_SIZE;
                        insert_to_record_fragment(tls_ciphertext_rcvbuf, cur->first+len_last_record+TLSHDR_SIZE, tlshdr->length, ciphertext, ciphertext_len);

                        cur->second.data_len = len_last_record;
                        cur_len = cur->second.data_len;

                        // print_hexdump(cur->second.data+len_last_record, len_new_record);
                    }
                    else{
                        printf("merge_record_fragment: header not found\n\n");
                        printf("After:\n");
                        print_hexdump(cur->second.data, cur->second.data_len);
                        printf("New header:\n");
                        print_hexdump(cur->second.data+cur->second.data_len, len_new_record);
                        exit(-1);
                    }
                }
            }

            unsigned char* new_data = (unsigned char*)malloc(prev_len+cur_len);
            memcpy(new_data, prev->second.data, prev_len);
            memcpy(new_data+prev_len, cur->second.data, cur_len);
            free(prev->second.data);
            free(cur->second.data);
            tls_ciphertext_rcvbuf.erase(cur++);
            // cur = prev;

            prev->second.data = new_data;
            prev->second.data_len = prev_len + cur_len;
            
            continue;
        }

        if(prev->second.record_size == prev->second.data_len){
            decrypt_whole_record(prev->second.data, prev->second.data_len);
            free(prev->second.data);
            tls_ciphertext_rcvbuf.erase(prev++);
            if(prev == tls_ciphertext_rcvbuf.end())
                break;
        }
        prev=cur;
        cur++;
    }
}

int insert_to_record_fragment(std::map<uint, struct record_fragment> &tls_ciphertext_rcvbuf, uint seq, int record_size, unsigned char* ciphertext, int ciphertext_len){

    unsigned char* temp_buf = (unsigned char*)malloc(ciphertext_len);
    if(!temp_buf){
        log_error("insert_to_recv_buffer: can't malloc for data_left");
        return -1;
    }
    memset(temp_buf, 0, ciphertext_len);
    memcpy(temp_buf, ciphertext, ciphertext_len);

    auto ret = tls_ciphertext_rcvbuf.insert( std::pair<uint , struct record_fragment>(seq, record_fragment(record_size, temp_buf, ciphertext_len)) );
    if (ret.second == false) {
        printf("tls_ciphertext_rcvbuf: %u already existed.\n", seq);
        if(ret.first->second.data_len < ciphertext_len){
            // printf("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            // log_error("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            free(ret.first->second.data);
            ret.first->second.data = NULL;
            ret.first->second.data = temp_buf;
            ret.first->second.data_len = ciphertext_len;
        }
        else
            return -1;
    }
    printf("insert_to_record_fragment: %u-(%d, %p, %d) inserted\n", seq, record_size, temp_buf, ciphertext_len);
    // merge_record_fragment(tls_ciphertext_rcvbuf);
    return 0;
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
        int read_bytes = 0;
        while(read_bytes < payload_len){
            unsigned char* remain_payload = payload+read_bytes;
            struct mytlshdr *tlshdr = (struct mytlshdr*)(remain_payload);

            if(tlshdr->version == 0x0303 || tlshdr->version == 0x0304){
                tlshdr->length = htons(tlshdr->length);
                unsigned char* ciphertext = remain_payload + TLSHDR_SIZE;
                int ciphertext_len = (tlshdr->length < payload_len - read_bytes - TLSHDR_SIZE)? tlshdr->length : payload_len - read_bytes - TLSHDR_SIZE;
                printf("process_tcp_packet: TLS Record: version %x, type %d, len %d(%x)\n\n", tlshdr->version, tlshdr->type, tlshdr->length, tlshdr->length);
                switch (tlshdr->type){
                    case TLS_TYPE_HANDSHAKE:
                    case TLS_TYPE_CHANGE_CIPHER_SPEC:
                    {
                        if(sport == 443)
                            seq_ini_rem = seq;
                        return 0;
                        break;
                    }
                    case TLS_TYPE_APPLICATION_DATA:
                    {
                        if(sport == 443 && key_obtained){
                            if(tlshdr->length > 8){
                                insert_to_record_fragment(tls_ciphertext_rcvbuf, seq+read_bytes+TLSHDR_SIZE, tlshdr->length, ciphertext, ciphertext_len);
                                merge_record_fragment(tls_ciphertext_rcvbuf);
                            }
                        }
                        break;
                    }
                    default:
                        printf("Unknown type: insert to buffer\n");
                        insert_to_record_fragment(tls_ciphertext_rcvbuf, seq+read_bytes, 0, payload+read_bytes, payload_len-read_bytes);
                        merge_record_fragment(tls_ciphertext_rcvbuf);
                        break;
                }
                read_bytes += ciphertext_len + TLSHDR_SIZE;
            }
            else{
                printf("TLS: fragment\n");
                if(sport == 443 && key_obtained)
                    if(payload_len > 8){
                        insert_to_record_fragment(tls_ciphertext_rcvbuf, seq+read_bytes, 0, payload+read_bytes, payload_len-read_bytes);
                        merge_record_fragment(tls_ciphertext_rcvbuf);
                    }
                break;
            }
        }
    }

    return 0;
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
        // printf("Received: len = %d\n%s\n\n", len, buf);
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

    SSL_CTX_set_tlsext_max_fragment_length(ctx, TLSEXT_max_fragment_length_1024);
    SSL_CTX_set_max_send_fragment(ctx, 1024);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("SSL_new() failed\n");
        return -1;
    }
    SSL_set_tlsext_max_fragment_length(ssl, TLSEXT_max_fragment_length_1024);
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
    
    char request[200];
    sprintf(request, "GET /pub/ubuntu/indices/md5sums.gz HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    SSL_write(ssl, request, strlen(request));
    printf("Write: %s\n\n", request);

    // unsigned char session_key[20],iv_salt[4];
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
    evp_cipher = EVP_get_cipherbyname("AES-128-GCM"); // Temporary Ugly hack here for Baidu.
    printf("evp_cipher: %p\n", evp_cipher);
    ssize_t key_length = EVP_CIPHER_key_length(evp_cipher);
    printf("key_length: %ld\n", key_length);

    get_write_key(ssl, digest_algorithm, evp_cipher, iv_salt, write_key_buffer);
    printf("iv_salt: ");
    for(int i = 0; i < 4; i++)
        printf("%02x", iv_salt[i]);
    printf("\n");

    key_obtained = true;

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

    strncpy(local_ip, "127.0.0.1", 16);
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
    tls_ciphertext_rcvbuf.clear();

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