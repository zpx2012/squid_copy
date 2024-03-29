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
#include <thread>
#include <mutex>


#ifdef USE_OPENSSL
struct subconn_info;

struct record_fragment{
    // bool is_header;
    unsigned char* data;//whole record, header and data
    int data_len;
    unsigned short* participated_subconns;
    record_fragment( unsigned char* dt, int dl){
        data = dt; data_len = dl;
    }
};
int insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint new_seq_start, unsigned char* new_data, int new_data_len);


#define MAX_FRAG_LEN 16384
#define MAX_GCM_RECORD_LEN (8+MAX_FRAG_LEN+16)
#define MAX_FULL_GCM_RECORD_LEN (TLSHDR_SIZE+MAX_GCM_RECORD_LEN)
uint get_record_num(unsigned int seq);

class TLS_Decrypted_Record_Reassembler;
class TLS_Decrypted_Records_Map;

class TLS_Crypto_Coder{
public:
    TLS_Crypto_Coder(const EVP_CIPHER * ec, unsigned char* salt, unsigned char* key, unsigned int vs_rvs, unsigned short lp);

    int partial_decrypt_record();
    int decrypt_record(uint64_t record_num, unsigned char* record_data, int record_len, unsigned char* plaintext);
    int generate_record(uint64_t record_num, unsigned char* plaintext, int len, unsigned char* record_buf);
    int get_aad(uint64_t record_num, int len, unsigned char* aad);


    unsigned short get_version_reversed(){
        return this->version_rvs;
    }

    bool get_key_obtained() {
        return this->key_obtained;
    }

    bool get_iv_xplct_ini_set(){
        return this->iv_xplct_ini_set;
    }
    
    void set_iv_explicit_init(unsigned char* iv_ex);

    int get_record_num_from_iv_explicit(unsigned char* iv_ex);

    uint get_plaintext_seq(uint ciphertext_seq){
        return ciphertext_seq / MAX_FULL_GCM_RECORD_LEN * (TLSHDR_SIZE + 8 + 16);
    }

    uint get_ciphtertext_seq(uint plaintext_seq){
        return (plaintext_seq) / MAX_FRAG_LEN * (TLSHDR_SIZE + 8 + 16);
    }

private:
    bool key_obtained = false, iv_xplct_ini_set = false;
    const EVP_CIPHER *evp_cipher;
    unsigned char iv_salt[5] = {0}, iv_xplct_ini[9] = {0}; // 4 to be modified
    unsigned long long iv_num_ini;
    unsigned char write_key_buffer[100] = {0}; // 100 to be modified
    // int record_size = 0, record_full_size = 0;
    unsigned short version_rvs;
    unsigned short local_port;
    // TLS_Decrypted_Records_Map* decrypted_records_map;
    friend TLS_Decrypted_Record_Reassembler;
};


class TLS_Encrypted_Record_Reassembler{
public:
    TLS_Encrypted_Record_Reassembler(int rs, int vs, TLS_Crypto_Coder* cc) { 
        record_full_size = rs;
        version_rvs = vs;
        crypto_coder = cc;
        tls_ciphertext_rcvbuf.clear(); 
    }
    int insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len);
    int merge_record_fragment();
    int merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);
    int decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf);
    int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf);

    bool empty(){
        return tls_ciphertext_rcvbuf.empty();
    }

    void lock();
    void unlock();
    // std::map<uint, struct record_fragment> tls_plaintext_rcvbuf;

private:
    int record_full_size, version_rvs;
    TLS_Crypto_Coder* crypto_coder;
    std::map<uint, struct record_fragment, std::less<uint>> tls_ciphertext_rcvbuf;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
};


class TLS_Decrypted_Record_Reassembler{
    // receive_buffer
    // tag_buffer
public:
    TLS_Decrypted_Record_Reassembler(int rn, int size);
    ~TLS_Decrypted_Record_Reassembler();
    int insert_plaintext(TLS_Crypto_Coder* cryto_coder, uint seq, u_char* data, int data_len);
    int insert_tag(TLS_Crypto_Coder* cryto_coder, uint offset, u_char* tag, int tag_len);
    int check_complete(u_char* buf, int buf_len, u_short* &return_ports, int& return_ports_len);
    int get_complete_plaintext(u_char* buf, int buf_len);
    bool verify(u_char* plntxt, int plntxt_len, TLS_Crypto_Coder* crypto_coder, u_char* tag);
    void cleanup();
    
    void lock();
    void unlock();

private:
    int record_num;
    int expected_size; //plaintext_len
    int record_size;

    Reassembler* plntxt_buffer;
    std::map<TLS_Crypto_Coder*, Reassembler*> tags;

    // std::mutex mutex;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    friend TLS_Decrypted_Records_Map;

};

class TLS_Decrypted_Records_Map{

public:
    TLS_Decrypted_Records_Map(TLS_Crypto_Coder* coder) { 
        main_subconn_cypto_coder = coder;
        decrypted_record_reassembler_map.clear(); 
        successful = failed = 0;
        // decrypted_record_reassembler_map = new TLS_Decrypted_Record_Reassembler*[42750];
        // mutex_map = new pthread_mutex_t[42750];
        // for (size_t i = 0; i < 42750; i++)
        // {
        //     decrypted_record_reassembler_map[i] = new TLS_Decrypted_Record_Reassembler(i, MAX_FRAG_LEN);
        //     mutex_map[i] = PTHREAD_MUTEX_INITIALIZER;
        // }
        
    }
    ~TLS_Decrypted_Records_Map();

    int insert_plaintext(int record_num, uint seq, u_char* data, int data_len, u_char* &return_str);
    // int insert_tag(int record_num, TLS_Crypto_Coder* cryto_coder, uint offset, u_char* tag, int tag_len, u_char* &return_str);
    // int inserted(int record_num, u_char* &return_str);
    // int insert(int record_num, TLS_Crypto_Coder* cryto_coder, uint seq, u_char* data, int data_len, u_char* &return_str);
    int insert(int record_num, int record_size, TLS_Crypto_Coder* cryto_coder, uint seq, u_char* data, int data_len, uint tag_offset, u_char* tag, int tag_len, u_char* &return_str, u_short* &return_ports, int& return_ports_len);
    int inserted(int record_num, TLS_Decrypted_Record_Reassembler* tls_decrpyted_record, u_char* &return_str, u_short* &return_ports, int& return_ports_len);
    
    TLS_Decrypted_Record_Reassembler* get_record_reassembler(int key){
        return decrypted_record_reassembler_map[key];
    }

    void print_result();

    void lock();
    void unlock();

private:
    // TLS_Decrypted_Record_Reassembler** decrypted_record_reassembler_map;
    std::map<int, TLS_Decrypted_Record_Reassembler*> decrypted_record_reassembler_map;
    // pthread_mutex_t* mutex_map;
    std::map<int, pthread_mutex_t> mutex_map;
    // std::map<uint, struct subconn_info*> *subconn_infos;
    TLS_Crypto_Coder* main_subconn_cypto_coder;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int successful, failed;
};


struct TLS_Record_Seq_Info{
    int record_num;
    int record_size_with_header;
    uint seq;//starting seq
    uint upper_seq;
    TLS_Record_Seq_Info(): record_num(0), record_size_with_header(0), seq(0), upper_seq(0) {}
    TLS_Record_Seq_Info(int rn, int rswh, uint s, uint us): record_num(rn), record_size_with_header(rswh), seq(s), upper_seq(us) {}
};


class TLS_Record_Number_Seq_Map{
public:
    TLS_Record_Number_Seq_Map();

    ~TLS_Record_Number_Seq_Map();
    TLS_Record_Seq_Info* insert(uint start_seq, int record_num, int record_size_with_header);
    TLS_Record_Seq_Info* insert_nolock(uint start_seq, int record_num, int record_size_with_header);
    // int insert(uint start_seq, TLS_Record_Seq_Info* seq_info);
    TLS_Record_Seq_Info* check_if_tlshdr(uint seq, unsigned char* payload, int payload_len, TLS_Crypto_Coder* crypto_coder);
    TLS_Record_Seq_Info* find_record_seq_info(uint seq, unsigned char* payload, int payload_len, TLS_Crypto_Coder* crypto_coder);
    int set_size(uint start_seq, int record_size_with_header);
    TLS_Record_Seq_Info* get_record_seq_info(uint seq);
    int get_record_num(uint seq);

    void print_record_seq_map();
    
    void set_localport(int lp){
        local_port = lp;
    }

    bool empty(){
        return tls_seq_map.empty();
    }

    void lock();
    void unlock();
private:
    int local_port;
    uint next_record_start_seq;
    int record_num_count;
    uint first_max_frag_seq, last_piece_start_seq;
    std::map<int, TLS_Record_Seq_Info*> tls_seq_map;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
};


unsigned char* merge_two_data(unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len);

// int process_tls_payload(bool in_coming, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local);
// int process_incoming_tls_payload(bool in_coming, unsigned int seq_tls_data, unsigned char* payload, int payload_len, subconn_info* subconn, TLS_Decrypted_Records_Map* decrypted_records_map, std::map<uint, struct record_fragment> &return_buffer);
// int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, subconn_info* subconn, TLS_Decrypted_Records_Map* decrypted_records_map, std::map<uint, struct record_fragment> &return_buffer);
int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf);
// int partial_decrypt_tcp_payload(struct subconn_info* subconn, uint seq, unsigned char* payload, int payload_len, TLS_Decrypted_Records_Map* decrypted_records_map, std::map<uint, struct record_fragment> &return_buffer);


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

#endif