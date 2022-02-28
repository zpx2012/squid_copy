#ifndef TLS_H
#define TLS_H
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
#include "reassembler.h"
#include "Optimack.h"

struct subconn_info;

struct record_fragment{
    // bool is_header;
    unsigned char* data;//whole record, header and data
    int data_len;
    record_fragment( unsigned char* dt, int dl){
        data = dt; data_len = dl;
    }
};

#define MAX_FRAG_LEN 2048
#define MAX_GCM_RECORD_LEN (8+MAX_FRAG_LEN+16)
#define MAX_FULL_GCM_RECORD_LEN (TLSHDR_SIZE+MAX_GCM_RECORD_LEN)
uint get_record_num(unsigned int seq);

class TLS_Decrypted_Records_Map;

class TLS_Crypto_Coder{
public:
    // int decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int partial_decrypt_record();
    int decrypt_record(uint64_t record_num, unsigned char* record_data, int record_len, unsigned char* plaintext);
    int generate_record(uint64_t record_num, unsigned char* plaintext, int len, unsigned char* record_buf);
    int get_aad(uint64_t record_num, int len, unsigned char* aad);

    void set_credentials(const EVP_CIPHER * ec, unsigned char* salt, unsigned char* key, unsigned short vs_rvs){
        this->evp_cipher = ec;
        
        memcpy(this->iv_salt, salt, 4);
        this->iv_salt[4] = 0;

        memcpy(this->write_key_buffer, key, 100);//100 to be modified
        this->write_key_buffer[99] = 0;

        this->key_obtained = true;

        this->version_rvs = vs_rvs;

    }

    unsigned short get_version_reversed(){
        return this->version_rvs;
    }

    bool get_key_obtained() {
        return this->key_obtained;
    }

    void set_iv_explicit_init(unsigned char* iv_ex){
        memcpy(this->iv_xplct_ini, iv_ex, 8);
        this->iv_xplct_ini[8] = 0;
    }

    uint get_plaintext_seq(uint ciphertext_seq){
        return ciphertext_seq / MAX_FULL_GCM_RECORD_LEN * (TLSHDR_SIZE + 8 + 16);
    }

    uint get_ciphtertext_seq(uint plaintext_seq){
        return (plaintext_seq) / MAX_FRAG_LEN * (TLSHDR_SIZE + 8 + 16);
    }

private:
    bool key_obtained = false;
    const EVP_CIPHER *evp_cipher;
    unsigned char iv_salt[5], iv_xplct_ini[9]; // 4 to be modified
    unsigned char write_key_buffer[100]; // 100 to be modified
    // int record_size = 0, record_full_size = 0;
    unsigned short version_rvs;

    // TLS_Decrypted_Records_Map* decrypted_records_map;
};


class TLS_Decrypted_Record_Reassembler{
    // receive_buffer
    // tag_buffer
public:
    TLS_Decrypted_Record_Reassembler(){
        plntxt_buffer = new Reassembler(0, REASSEM_TCP);
        expected_size = MAX_FRAG_LEN;
        tags.clear();
    }
    ~TLS_Decrypted_Record_Reassembler(){
        delete [] plntxt_buffer;
    }
    int insert_plaintext(uint seq, u_char* data, int data_len);
    int insert_tag(int conn_id, uint offset, u_char* tag, int tag_len);
    int check_complete();
    int get_complete_plaintext(u_char* buf);
    
    void lock(){
        pthread_mutex_lock(&mutex);
    }

    void unlock(){
        pthread_mutex_unlock(&mutex);
    }

private:
    Reassembler* plntxt_buffer;
    // TLS_Decrypted_Records_Map tags;
    std::map<int, Reassembler> tags;
    int expected_size;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
};


class TLS_Decrypted_Records_Map{

public:
    TLS_Decrypted_Records_Map() { decrypted_record_reassembler_map.clear(); }
    ~TLS_Decrypted_Records_Map() {}
    int insert_plaintext(int record_num, uint seq, u_char* data, int data_len);
    int insert_tag(int record_num, int conn_id,uint offset, u_char* tag, int tag_len);
    int inserted(int record_num);
private:
    std::map<int, TLS_Decrypted_Record_Reassembler> decrypted_record_reassembler_map;
    std::map<uint, struct subconn_info*> *subconn_infos;
};


unsigned char* merge_two_data(unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);

// int process_tls_payload(bool in_coming, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);
int process_incoming_tls_payload(bool in_coming, unsigned int seq_tls_data, unsigned char* payload, int payload_len); // TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);
int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len); // TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);

void set_tls_handshake_hello_extension_max_frag_len(unsigned char *extension, unsigned char dst);
int alter_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len, bool from_server, unsigned char src, unsigned char dst);
unsigned char* find_pos_tls_handshake(unsigned char* tcp_payload, int tcp_payload_len);
unsigned char* find_pos_tls_handshake_hello(unsigned char* data, int data_len);
unsigned char* find_pos_tls_handshake_hello_extensions(unsigned char* data, int data_len);
unsigned char* find_pos_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len);


void get_write_key(SSL *s, const EVP_MD *md, const EVP_CIPHER *evp_cipher, unsigned char *iv_salt, unsigned char *write_key_buffer);
int print_hexdump(unsigned char* hexdump, int len);

SSL* open_ssl_conn(int sockfd, bool limit_recordsize);

#endif