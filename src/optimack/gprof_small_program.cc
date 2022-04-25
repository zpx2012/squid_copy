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
        if(count >= 2000000) // 29980133
            break;
        if(len == 0)
            break;
        if(len<0){
            printf("Receive error\n");
            usleep(100);
            continue;
        }
        buf[len]=0;
        // printf("RecvPacket: Received Record No.%d, len = %d\n\n", ++count, len);
//        fprintf(fp, "%s",buf);
    } while(true);
    // } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ){
            printf("SSL_r ead_error: SSL_ERROR_WANT_READ\n");
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
    return 0;
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

    Optimack optimack;

    strncpy(local_ip, "169.235.25.244", 16);

    int sockfd = establish_tcp_connection(0, remote_ip, remote_port);
    local_port = get_localport(sockfd);
    SSL* ssl = open_ssl_conn(sockfd, false);
    // local_port = 36000;

    printf("Local IP: %s\n", local_ip);
    printf("Local Port: %d\n", local_port);
    printf("Remote IP: %s\n", remote_ip);
    printf("Remote Port: %d\n", remote_port);

    optimack.init();
    optimack.setup_nfq(local_port);
    optimack.nfq_stop = 0;
    optimack.setup_nfqloop();
    optimack.open_duplicate_conns(remote_ip, local_ip, remote_port, local_port, sockfd);
    optimack.open_duplicate_ssl_conns(ssl);

    char request[400];
    sprintf(request, "GET /ubuntu/indices/md5sums.gz HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    // sprintf(request, "GET /ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n", remote_domain);
    SendRequest(ssl, request, strlen(request));
    optimack.send_request(request, strlen(request));

    RecvPacket(ssl);
    SSL_free(ssl);
    close(sockfd);
    // SSL_CTX_free(ctx);

}