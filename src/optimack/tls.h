#include "hping2.h"

#include <pthread.h>
#include <openssl/ssl.h>

#include <map>
#include <utility>
#include <iterator>
#include <functional>
#include <algorithm>
#include <cstdlib>
#include <string>
#include <sstream>
#include <string.h>
// #include <stdint.h>

struct record_fragment{
    // bool is_header;
    unsigned char* data;//whole record, header and data
    int data_len;
    record_fragment( unsigned char* dt, int dl){
        data = dt; data_len = dl;
    }
};

#define MAX_FRAG_LEN 512
#define MAX_GCM_RECORD_LEN (8+MAX_FRAG_LEN+16)
#define MAX_FULL_GCM_RECORD_LEN (TLSHDR_SIZE+MAX_GCM_RECORD_LEN)
uint get_record_num(unsigned int seq);

class TLS_rcvbuf{
public:
    TLS_rcvbuf() { tls_ciphertext_rcvbuf.clear(); printf("Initialize here.\n"); }
    int insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len);
    int merge_record_fragment();
    int merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);
    int decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int partial_decrypt_tcp_payload(uint seq, unsigned char* payload, int payload_len);
    int partial_decrypt_record();
    int decrypt_record(uint seq, unsigned char* record_data, int record_len, unsigned char* plaintext);
    int generate_record(uint seq, unsigned char* plaintext, int len, unsigned char* record_buf);
    int get_aad(uint64_t record_num, int len, unsigned char* aad);

    void set_credentials(const EVP_CIPHER * ec, unsigned char* salt, unsigned char* key, int rs, unsigned short vs_rvs){
        this->evp_cipher = ec;
        
        memcpy(this->iv_salt, salt, 4);
        this->iv_salt[4] = 0;

        memcpy(this->write_key_buffer, key, 100);//100 to be modified
        this->write_key_buffer[99] = 0;

        this->record_size = rs;
        this->record_full_size = TLSHDR_SIZE + 8 + rs + 16;

        this->key_obtained = true;

        this->version_rvs = vs_rvs;

        tls_ciphertext_rcvbuf.clear();
    }

    unsigned short get_version_reversed(){
        return this->version_rvs;
    }

    bool get_key_obtained() {
        return this->key_obtained;
    }

    // uint get_seq_data_start() {
    //     return this->seq_data_start;
    // }

    // void set_seq_data_start(uint sds){
    //     this->seq_data_start = sds;
    // }

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

    bool empty(){
        return tls_ciphertext_rcvbuf.empty();
    }
    // std::map<uint, struct record_fragment> tls_plaintext_rcvbuf;

private:
    int insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint seq, unsigned char* ciphertext, int ciphertext_len);

    bool key_obtained = false;
    const EVP_CIPHER *evp_cipher;
    unsigned char iv_salt[5], iv_xplct_ini[9]; // 4 to be modified
    unsigned char write_key_buffer[100]; // 100 to be modified
    // uint seq_data_start = 0;
    int record_size = 0, record_full_size = 0;
    unsigned short version_rvs;
    std::map<uint, struct record_fragment, std::less<uint>> tls_ciphertext_rcvbuf;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
};

unsigned char* merge_two_data(unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);

// int process_tls_payload(bool in_coming, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);
int process_incoming_tls_payload(bool in_coming, unsigned int seq_tls_data, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);
int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);

void set_tls_handshake_hello_extension_max_frag_len(unsigned char *extension, unsigned char dst);
int alter_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len, bool from_server, unsigned char src, unsigned char dst);
unsigned char* find_pos_tls_handshake(unsigned char* tcp_payload, int tcp_payload_len);
unsigned char* find_pos_tls_handshake_hello(unsigned char* data, int data_len);
unsigned char* find_pos_tls_handshake_hello_extensions(unsigned char* data, int data_len);
unsigned char* find_pos_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len);


void get_write_key(SSL *s, const EVP_MD *md, const EVP_CIPHER *evp_cipher, unsigned char *iv_salt, unsigned char *write_key_buffer);
int print_hexdump(unsigned char* hexdump, int len);

SSL* open_ssl_conn(int sockfd, bool limit_recordsize);
