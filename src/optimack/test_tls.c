#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "get_server_key.h"

// void test_write_key(SSL *s){
//     if(!s)
//         return;

//     unsigned char session_key[20],iv_salt[4];
//     get_server_session_key_and_iv_salt(s, iv_salt, session_key);
//     printf("get write salt: ");
//     for(int i = 0; i < 4; i++)
//         printf("%02x", iv_salt[i]);
//     printf("\n");

//     printf("get server key: ");
//     for(int i = 0; i < 20; i++)
//         printf("%02x", session_key[i]);
//     printf("\n");
//     return;
// }

int RecvPacket(SSL *ssl)
{
    int len=100;
    char buf[1000000];
    do {
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        printf("%s\n",buf);
//        fprintf(fp, "%s",buf);
    } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
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
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "SSL_new() failed\n");
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
        fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
        return -1;
    }
    STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        printf(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    }
    printf("\n");
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    test_write_key(ssl);
    const char *chars = "Hello World, 123!";
    SSL_write(ssl, chars, strlen(chars));
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
    server_addr.sin_addr.s_addr = inet_addr("18.7.29.125");
    server_addr.sin_port = htons(443);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        close(sockfd);
    }

    return sockfd;
}

int main(){
    int sockfd = establish_tcp_connection();
    open_ssl_conn(sockfd);
    // RecvPacket();
}