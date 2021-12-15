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

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include "logging.h"
#include "util.h"
#include "hping2.h"
// #include "socket.h"
#include "thr_pool.h"

//Original 
#define LOGSIZE 10240
int nfq_stop;
thr_pool_t* pool;
char local_ip[16];
unsigned short local_port;
char remote_ip[16];
unsigned short remote_port = 443;

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

typedef enum
{
    TLS_TYPE_NONE               = 0,
    TLS_TYPE_CHANGE_CIPHER_SPEC = 20,
    TLS_TYPE_ALERT              = 21,
    TLS_TYPE_HANDSHAKE          = 22,
    TLS_TYPE_APPLICATION_DATA   = 23,
    TLS_TYPE_HEARTBEAT          = 24,
    TLS_TYPE_ACK                = 25  //RFC draft
} TlsContentType;
struct TLSHeader{
    unsigned char type;
    unsigned short version;
    unsigned short length;
    unsigned char* ciphertext;
};

int process_tcp_packet(struct thread_data* thr_data)
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

    printf("P%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d\n", thr_data->pkt_id, remote_ip, sport, local_ip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq, tcphdr->th_ack, ack, iphdr->ttl, payload_len);

    if(payload_len){
        struct TLSHeader *tlshdr = (struct TLSHeader*)payload;
        printf("TLS Handshake: type %d letting through\n\n", tlshdr->type);
    }
    // if( tlshdr->type == TLS_TYPE_HANDSHAKE || tlshdr->type == TLS_TYPE_CHANGE_CIPHER_SPEC){
    //     return 0;
    // }

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
    char buf[1000000];
    do {
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        printf("Received: %s, len = %d\n", buf, len);
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
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("SSL_CTX_new() failed\n");
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("SSL_new() failed\n");
        return -1;
    }
    SSL_set_fd(ssl, fd);
    const char* const PREFERRED_CIPHERS = "TLS_AES_128_GCM_SHA256";
    SSL_CTX_set_ciphersuites(ctx, PREFERRED_CIPHERS);
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
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    // test_write_key(ssl);
    const char *chars = "GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n";
    SSL_write(ssl, chars, strlen(chars));
    printf("Write: %s\n", chars);
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

int main(int argc, char *argv[])
{
    int opt;

    if (argc < 1) {
        printf("Usage: %s <remote_ip> <remote_port> <local_port> <ack_pacing> \n", argv[0]);
        exit(-1);
    }

    strncpy(remote_ip, argv[1], 16);
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

    // start the nfq proxy thread
    nfq_stop = 0;
    pthread_t nfq_thread;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, NULL) != 0){
        log_error("Fail to create nfq thread.");
        exit(EXIT_FAILURE);
    }
    printf("created nfq thread\n");

    // int sockfd = establish_tcp_connection();
    // local_port = get_localport(sockfd);
    local_port = 36000;
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
    while(true);
    // open_ssl_conn(sockfd);
    printf("After calling open_ssl_conn()\n");

    // cleanup();
    teardown_nfq();

    sprintf(cmd, "iptables -D INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);

    sprintf(cmd, "iptables -D OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    system(cmd);
}