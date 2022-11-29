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
#include <fcntl.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include "Optimack_gprof.h"
// #include "logging.h"
// #include "util.h"
// #include "hping2.h"
// #include "socket.h"
// #include "thr_pool.h"

// #include "tls.h"

//Original 
#define LOGSIZE 10240
int nfq_stop;
thr_pool_t* pool;
char local_ip[16];
char remote_ip[16];
unsigned short local_port;
unsigned short remote_port = 443;
char *remote_domain;
bool handshake_done = false;


int SendRequest(SSL *ssl, char* request, int request_len){
    SSL_write(ssl, request, strlen(request));
    // printf("Write: %s\n\n", request);
    return 0;
}


int RecvPacket(SSL *ssl)
{
    int len=100, count = 0;
    char buf[4001];
    do {
        len=SSL_read(ssl, buf, 4000);
        count += len;
        // if(count >= 87548090) {// 29980133
        //     printf("RecvPacket: exits.\n");
        //     break;
        // }
        if (len > 0)
            printf("RecvPacket: recved %d bytes.\n", len);
        else if(len == 0)
            break;
        else if(len < 0){
            printf("Receive error\n");
            int err = SSL_get_error(ssl, len);
            if (err == SSL_ERROR_WANT_READ){
                printf("SSL_read_error: SSL_ERROR_WANT_READ\n");
            }
            if (err == SSL_ERROR_WANT_WRITE){
                printf("SSL_read_error: SSL_ERROR_WANT_WRITE\n");
            }
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL){
                printf("SSL_read_error: %d\n", err);
            }
            usleep(100);
            continue;
        }
        buf[len]=0;
        // printf("RecvPacket: Received Record No.%d, len = %d\n\n", ++count, len);
//        fprintf(fp, "%s",buf);
    } while(true);
    
    printf("RecvPacket: exits. new\n");

    return 0;
}

SSL * open_ssl_conn_blocking(int sockfd, bool limit_recordsize){
    if(sockfd == 0){
        printf("open_ssl_conn: sockfd can't be 0!Q\n");
    }
    
    printf("open_ssl_conn: for fd %d\n", sockfd);
    
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == nullptr)
    {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return nullptr;
    }
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    
    int max_frag_len_version = std::log2(MAX_FRAG_LEN / 256);
    if(limit_recordsize){
        SSL_CTX_set_tlsext_max_fragment_length(ctx, max_frag_len_version);
        // SSL_CTX_set_max_send_fragment(ctx, MAX_FRAG_LEN);
    }
    
    SSL *ssl = SSL_new(ctx);
    if (ssl == nullptr)
    {
        fprintf(stderr, "SSL_new() failed\n");
        return nullptr;
    }
    if(limit_recordsize)
        SSL_set_tlsext_max_fragment_length(ssl, max_frag_len_version);
    
    SSL_set_fd(ssl, sockfd);

    const char* const PREFERRED_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256";
    // SSL_CTX_set_ciphersuites(ctx, PREFERRED_CIPHERS);
    SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS);

    const int status = SSL_connect(ssl);
    if (status != 1)
    {
        SSL_get_error(ssl, status);
        fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
        return nullptr;
    }
    printf("open_ssl_conn: fd %d Connected with %s encryption\n", sockfd, SSL_get_cipher(ssl));

    // STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    // for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
    //     printf("%s", SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    // }
    // free(sk);
    SSL_CTX_free(ctx);

    return ssl;
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

void test_optimack(char* remote_ip, char* local_ip, short remote_port, short local_port, int sockfd, SSL* ssl){
    std::shared_ptr<Optimack> optimack = std::make_shared<Optimack>();

    optimack->init();
    optimack->setup_nfq(local_port);
    optimack->nfq_stop = 0;
    optimack->setup_nfqloop();
    optimack->set_main_subconn(remote_ip, local_ip, remote_port, local_port, sockfd);
    sleep(2);
    optimack->set_main_subconn_ssl(ssl);
    sleep(10);

    char request[400];
    //https://mirrors.cat.pdx.edu/centos/2/centos2-scripts-v1.tar
    sprintf(request, "GET /centos/2/centos2-scripts-v1.tar HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    // sprintf(request, "GET /ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    optimack->send_request(request, strlen(request));
    SendRequest(ssl, request, strlen(request));

    RecvPacket(ssl);
    optimack->cleanup();
 
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
    strncpy(local_ip, "119.23.104.145", 16);

    int sockfd = establish_tcp_connection(0, remote_ip, remote_port);
    local_port = get_localport(sockfd);
    SSL* ssl = open_ssl_conn_blocking(sockfd, false);
    // local_port = 36000;

    printf("Local IP: %s\n", local_ip);
    printf("Local Port: %d\n", local_port);
    printf("Remote IP: %s\n", remote_ip);
    printf("Remote Port: %d\n", remote_port);

    test_optimack(remote_ip, local_ip, remote_port, local_port, sockfd, ssl);
    sleep(10);
   // SSL_CTX_free(ctx);
    SSL_free(ssl);
    close(sockfd);

}