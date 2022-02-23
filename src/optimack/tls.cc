#include "tls.h"
#include "logging.h"
#include <bits/stdc++.h>

#include "get_server_key_single.h"

int print_hexdump(unsigned char* hexdump, int len){
    for(int i = 0; i < len; i++){
        printf("%02x ", hexdump[i]);
        if(i % 16 == 15)
            printf("\n");
    }
    printf("\n\n");
}

//All seq is seq since tls_application_data

int TLS_rcvbuf::insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len){
    return insert_to_rcvbuf(tls_ciphertext_rcvbuf, seq, ciphertext, ciphertext_len);
}

int TLS_rcvbuf::insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint new_seq_start, unsigned char* new_data, int new_data_len){
    unsigned char* temp_buf = (unsigned char*)malloc(new_data_len);
    if(!temp_buf){
        log_error("insert_to_rcvbuf: can't malloc for %d bytes", new_data_len);
        return -1;
    }
    memset(temp_buf, 0, new_data_len);
    memcpy(temp_buf, new_data, new_data_len);

    auto ret = tls_rcvbuf.insert( std::pair<uint , struct record_fragment>(new_seq_start, record_fragment(temp_buf, new_data_len)) );
    if (ret.second == false) {
        log_error("tls_ciphertext_rcvbuf: %u already existed.\n", new_seq_start);
        if(ret.first->second.data_len < new_data_len){
            log_info("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.data_len, new_data_len);
            // log_error("recv_buffer: old len %d < new len %d. Erase old one, replace with new onw\n", ret.first->second.len, len);
            free(ret.first->second.data);
            ret.first->second.data = NULL;
            ret.first->second.data = temp_buf;
            ret.first->second.data_len = new_data_len;
        }
        else{
            free(temp_buf);
            return -1;
        }
    }
    log_info("insert_to_record_fragment: %u-(%p, %d)-%u inserted", new_seq_start, temp_buf, new_data_len, new_seq_start+new_data_len);
    return 0;
}

int TLS_rcvbuf::merge_record_fragment(){
    if(tls_ciphertext_rcvbuf.empty())
        return -1;
    for(auto prev = tls_ciphertext_rcvbuf.begin(), cur=std::next(prev); prev != tls_ciphertext_rcvbuf.end();){
        int prev_len = prev->second.data_len, cur_len = cur->second.data_len;

        if(prev->first + prev_len == cur->first){
            log_info("merge_record_fragment: %u-(%p, %d) and %u-(%p, %d)", prev->first, prev->second.data, prev->second.data_len, cur->first, cur->second.data, cur->second.data_len);
            merge_two_record_fragment(&prev->second, prev->second.data, prev->second.data_len, cur->second.data, cur->second.data_len);
            tls_ciphertext_rcvbuf.erase(cur++);
            continue;
        }
        prev=cur;
        cur++;
    }
    return 0;
}

int TLS_rcvbuf::merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len){
    frag->data = merge_two_data(first_data, first_data_len, second_data, second_data_len);
    frag->data_len = first_data_len + second_data_len;
    return 0;
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


int TLS_rcvbuf::decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    //Use seq to find the header
    if(tls_ciphertext_rcvbuf.empty())
        return -1;
    
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

int TLS_rcvbuf::decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    int decrypt_start_local = (seq/record_full_size*record_full_size+1) - seq;
    int decrypt_end_local;
    if(decrypt_start_local < 0){
        // printf("decrypt_one_payload: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d), add to %d\n", decrypt_start_local, seq_data_start, seq, payload, payload_len, decrypt_start_local+record_full_size);
        decrypt_start_local += record_full_size;
        if(decrypt_start_local > payload_len){//doesn't contain one full record size
            decrypt_start = decrypt_end = 0;
            return -1;
        }
        // exit(-1);
    }

    for(decrypt_end_local = decrypt_start_local; decrypt_end_local+record_full_size <= payload_len; decrypt_end_local += record_full_size){
        struct mytlshdr* tlshdr = (struct mytlshdr*)(payload+decrypt_end_local);
        int tlshdr_len = htons(tlshdr->length);
        log_info("TLS Record: version %04x, type %d, len %d(%x), offset %d", tlshdr->version, tlshdr->type, tlshdr_len, tlshdr_len, decrypt_end_local);

        if(!( tlshdr->version == version_rvs && tlshdr->type == TLS_TYPE_APPLICATION_DATA ) ){
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
            unsigned char plaintext[MAX_FRAG_LEN+1] = {0};//
            int plaintext_len = decrypt_record(seq+decrypt_end_local, payload+decrypt_end_local, tlshdr_len + TLSHDR_SIZE, plaintext);
            if(plaintext_len > 0)
                insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, plaintext, plaintext_len);
            // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, payload+decrypt_end_local, record_full_size);
        }
    }
    decrypt_start = decrypt_start_local;
    decrypt_end = decrypt_end_local;
    return 0;
}

//Assuming the record size doesn't change in the all-but-the-last records
int TLS_rcvbuf::partial_decrypt_tcp_payload(uint seq, unsigned char* payload, int payload_len){
    int payload_index_record_start, payload_index_record_end; 
    
    for(payload_index_record_start = (seq/record_full_size*record_full_size+1) - seq, payload_index_record_end = payload_index_record_start + record_full_size - 1; 
        payload_index_record_start < payload_len-1; 
        payload_index_record_start = payload_index_record_end+1, payload_index_record_end += record_full_size)
    {
        unsigned char ciphertext[MAX_FULL_GCM_RECORD_LEN+1] = {0},
                      plaintext[MAX_FRAG_LEN+1] = {0};
        int payload_index_partial_start = 0, 
            record_index_partial_start = 0,
            partial_len = MAX_FULL_GCM_RECORD_LEN;
        if(payload_index_record_start >= 0){
            payload_index_partial_start = payload_index_record_start;
            record_index_partial_start = 0;
            partial_len = (payload_index_record_end >= payload_len-1)? payload_len - payload_index_record_start : record_full_size;
        }
        else{
            payload_index_partial_start = 0;
            record_index_partial_start = -payload_index_record_start;
            partial_len = (payload_index_record_end >= payload_len-1)? payload_len : payload_index_record_end;
        }
        memcpy(ciphertext + record_index_partial_start, payload + payload_index_partial_start, partial_len);
        int ret = decrypt_record(seq + payload_index_record_start, ciphertext, MAX_FULL_GCM_RECORD_LEN, plaintext);
        int plaintext_index_partial_start, plaintext_partial_len = partial_len;
        if(record_index_partial_start <= TLSHDR_SIZE + 8){
            plaintext_index_partial_start = 0;
            plaintext_partial_len -= TLSHDR_SIZE + 8;
        }
        if(payload_index_record_end <= payload_len-1){
            plaintext_partial_len -= 16;
            //copy tag to record object
        }
        //store 
        printf("Partial decrypt: %s\n", plaintext+plaintext_index_partial_start);
    }


    // if(decrypt_start_local < 0){
    //     // printf("decrypt_one_payload: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d), add to %d\n", decrypt_start_local, seq_data_start, seq, payload, payload_len, decrypt_start_local+record_full_size);
    //     decrypt_start_local += record_full_size;
    //     if(decrypt_start_local > payload_len){//doesn't contain one full record size
    //         decrypt_start = decrypt_end = 0;
    //         return -1;
    //     }
    //     // exit(-1);
    // }
}


int TLS_rcvbuf::decrypt_record(uint seq, unsigned char* record_data, int record_len, unsigned char* plaintext){
    if(record_len <= 8 + TLSHDR_SIZE)
        return -1;        

    unsigned char* appdata = record_data + TLSHDR_SIZE;
    int appdata_len = record_len - TLSHDR_SIZE;

    unsigned char* ciphertext = appdata + 8;
    int ciphertext_len = appdata_len - 8 - 16;

    if(seq == 1)
        set_iv_explicit_init(appdata);

    unsigned char iv[13] = {0};
    memcpy(iv, iv_salt, 4);
    memcpy(iv+4, appdata, 8);
    iv[12] = 0;

    unsigned char aad[14] = {0};
    uint64_t record_num = get_record_num(seq);
    get_aad(record_num, ciphertext_len, aad);
    int ret = gcm_decrypt(ciphertext, ciphertext_len, evp_cipher, aad, 9, write_key_buffer, iv, 12, plaintext, record_data+record_len-16);
    if(ret > 0) {
        log_info("decrypt_record: Record No.%lu, decrypted %d bytes", record_num, ret);
        plaintext[ret] = 0;
    }
    else {
        log_info("decrypt_record: Record No.%lu, fail to decrypt %d bytes", record_num, ret);
    }
    return ret;
}

int TLS_rcvbuf::generate_record(uint seq, unsigned char* plaintext, int len, unsigned char* record_buf){
    //len > record_size?
    
    record_buf[0] = TLS_TYPE_APPLICATION_DATA;
    *((uint16_t*)(record_buf+1)) = version_rvs;
    *((uint16_t*)(record_buf+3)) = ntohs(len+8+16);

    unsigned char iv[13];
    uint64_t record_num = get_record_num(seq);
    memcpy(iv, iv_salt, 4);
    unsigned long long iv_num = htobe64(*((unsigned long long*)iv_xplct_ini));
    iv_num = htobe64(iv_num+record_num-1);
    memcpy(iv+4, &iv_num, 8);
    iv[12] = 0;
    // printf("IV ini:");
    // print_hexdump(iv_xplct_ini, 8);
    // printf("IV:");
    // print_hexdump(iv+4, 8);
    memcpy(record_buf+TLSHDR_SIZE, iv+4, 8);

    unsigned char aad[14];
    get_aad(record_num, len, aad);
    int record_len = TLSHDR_SIZE+8+len+16;
    int ret = gcm_encrypt(plaintext, len, evp_cipher, aad, 13, write_key_buffer, iv, 12, record_buf+TLSHDR_SIZE+8, record_buf+record_len-16);
    if(ret > 0){
        record_buf[record_len] = 0;
        log_info("generate_record: Record No.%lu, encrypted %d bytes", record_num, ret);
        return record_len;
    }
    else{
        log_info("generate_record: Record No.%lu, fail to encrypt %d bytes", record_num, ret);
        return -1;
    }
}

uint get_record_num(unsigned int seq){
    uint mode = (seq+MAX_FULL_GCM_RECORD_LEN-1) % MAX_FULL_GCM_RECORD_LEN;
    if(mode != 0){
        log_info("Not full divide: seq(%u %x)-1+MAX_FULL_GCM_RECORD_LEN mod record_full_size(%d) = %d\n", seq, seq, MAX_FULL_GCM_RECORD_LEN, mode);
    }
    return (seq+MAX_FULL_GCM_RECORD_LEN+1)/MAX_FULL_GCM_RECORD_LEN;
}


int TLS_rcvbuf::get_aad(uint64_t record_num, int len, unsigned char* aad){
    record_num = htobe64(record_num);
    memcpy(aad, &record_num, 8);
    aad[8] = TLS_TYPE_APPLICATION_DATA;
    *((uint16_t*)(aad+9)) = version_rvs;
    *((uint16_t*)(aad+11)) = ntohs(len);
    aad[13] = 0;
}



int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

    // if(!tls_rcvbuf.get_key_obtained() || !tls_rcvbuf.get_seq_data_start()){
    //     bool is_valid = true;
    //     tls_rcvbuf.lock();
    //     if(!tls_rcvbuf.get_key_obtained()){
    //         is_valid = false;
    //     }
    //     else if(!tls_rcvbuf.get_seq_data_start()){
    //         if(contains_header){
    //             tls_rcvbuf.set_seq_data_start(seq);
    //             tls_rcvbuf.set_iv_explicit_init(payload+TLSHDR_SIZE);
    //         }
    //         else
    //             is_valid = false;
    //     }
    //     tls_rcvbuf.unlock();
    //     if(!is_valid)
    //         return 0;
    // }


    int decrypt_start = 0, decrypt_end = 0;
    tls_rcvbuf.decrypt_one_payload(seq, payload, payload_len, decrypt_start, decrypt_end, plaintext_buf_local);
    tls_rcvbuf.partial_decrypt_tcp_payload(seq, payload, payload_len);

    if(decrypt_start != 0 || decrypt_end != payload_len){
        tls_rcvbuf.lock();
        if(decrypt_end < payload_len){
            tls_rcvbuf.insert_to_record_fragment(seq+decrypt_end, payload+decrypt_end, payload_len-decrypt_end);
        }
        if(decrypt_start){
            tls_rcvbuf.insert_to_record_fragment(seq, payload, decrypt_start);
        }
        if(!tls_rcvbuf.empty()) {
            tls_rcvbuf.merge_record_fragment();
            tls_rcvbuf.decrypt_record_fragment(plaintext_buf_local);
        }
        tls_rcvbuf.unlock();
    }
    return 1;
}

// int process_incoming_tls_payload(unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

// }

// int process_outgoing_tls_payload(unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

// }

//return verdict
int process_incoming_tls_payload(bool in_coming, unsigned int seq_tls_data, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

    if(!in_coming)
        return -1;

    struct mytlshdr *tlshdr = (struct mytlshdr*)(payload);
    int tlshdr_len = htons(tlshdr->length);

    if(tlshdr->version == tls_rcvbuf.get_version_reversed()){
        if(tlshdr->type == TLS_TYPE_APPLICATION_DATA && tlshdr_len > 8){
            return process_incoming_tls_appdata(true, seq_tls_data, payload, payload_len, tls_rcvbuf, plaintext_buf_local);
        }
        else{
            printf("Unknown type: %d or tlshdr_len %d <= 8\n", tlshdr->type, tlshdr_len);
            return -1;
        }
    }
    else{
        return process_incoming_tls_appdata(false, seq_tls_data, payload, payload_len, tls_rcvbuf, plaintext_buf_local);
    }
}


void get_write_key(SSL *s, const EVP_MD *md, const EVP_CIPHER *evp_cipher, unsigned char *iv_salt, unsigned char *write_key_buffer){
    if(!s)
        return;

    // unsigned char iv_salt[4]; // 4 to be modified
    // unsigned char write_key_buffer[100]; // 100 to be modified
    int iv_len;
    int write_key_buffer_len;
    // get_server_session_key_and_iv_salt(s, iv_salt, session_key); // This function is obsolete.
    iv_len = get_server_write_iv_salt(s, iv_salt, md, evp_cipher);
    printf("iv_len: %ld\n", iv_len);
    write_key_buffer_len = get_server_write_key(s, write_key_buffer, md, evp_cipher);
    printf("write_key_buffer_len: %ld\n", write_key_buffer_len);
    
    printf("get_server_write_key: ");
    for (int i = 0; i < write_key_buffer_len; i++)
        printf("%02x", write_key_buffer[i]);
    printf("\n");

    printf("get_server_write_iv_salt: ");
    for(int i = 0; i < 4; i++)
        printf("%02x", iv_salt[i]);
    printf("\n");
    return;
}

SSL * open_ssl_conn(int sockfd, bool limit_recordsize){
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    
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
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        printf(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    }

    return ssl;
}



typedef enum
{
    TLS_HANDSHAKE_CLIENT_HELLO               = 1,
    TLS_HANDSHAKE_SERVER_HELLO               = 2
} TlsHandshakeType;


int alter_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len, bool from_server, unsigned char src, unsigned char dst){
    
    if(!data){
        printf("alter_tls_handshake_hello_extension_max_frag_len: [Error] empty data!\n");
        return -1;
    }

    unsigned char* tls_hdsk = find_pos_tls_handshake(data, data_len);
    if(!tls_hdsk)
        return -1;

    unsigned char* tls_hdsk_hello = find_pos_tls_handshake_hello(tls_hdsk, data_len);
    unsigned char* tls_hdsk_hello_exts = find_pos_tls_handshake_hello_extensions(tls_hdsk_hello, data_len); 
    unsigned char* tls_hdsk_hello_ext_max_frag_len = find_pos_tls_handshake_hello_extension_max_frag_len(tls_hdsk_hello_exts, data_len);

    if(!tls_hdsk_hello_ext_max_frag_len){
        log_error("alter_tls_handshake_hello_extension_max_frag_len: [Error] max_frag_len not found!\n");
        return -1;
    }

    unsigned char hello_type = *tls_hdsk_hello;
    unsigned char max_frag_len_val = *tls_hdsk_hello_ext_max_frag_len;
    if((!from_server && hello_type == TLS_HANDSHAKE_CLIENT_HELLO) || (from_server && hello_type == TLS_HANDSHAKE_SERVER_HELLO)){
        if(max_frag_len_val == src){
            *tls_hdsk_hello_ext_max_frag_len = dst;
            printf("alter_tls_handshake_hello_extension_max_frag_len: successfully alter value from %u to %u\n", src, dst);
            return 0;
        }
        else{
            printf("alter_tls_handshake_hello_extension_max_frag_len: [Error]: max_frag_len orig value(%u) not matching dst value(%u)\n", src, dst);
            return -1;
        }
    }
    else{
        printf("alter_tls_handshake_hello_extension_max_frag_len: [Error]: direction(%u) not matching hello type(%u)\n", from_server, hello_type);
        return -1;
    }

}


// int process_tls_payload(bool in_coming, unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){
unsigned char* find_pos_tls_handshake(unsigned char* tcp_payload, int tcp_payload_len){
    
    if (!tcp_payload){
        printf("[Error]: find_pos_tls_handshake: empty data!\n");
        return NULL;
    }

    int pos = 0;

    while(pos < tcp_payload_len){
        unsigned char* remain_payload = tcp_payload+pos;
        struct mytlshdr *tlshdr = (struct mytlshdr*)(remain_payload);
        int tlshdr_len = htons(tlshdr->length);

        if(tlshdr->type == TLS_TYPE_HANDSHAKE)
            return remain_payload;

        pos += tlshdr_len + TLSHDR_SIZE;
    }
    return NULL;
}


/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
unsigned char* find_pos_tls_handshake_hello(unsigned char* data, int data_len){
    
    if(!data){
        log_error("[Error]: find_pos_tls_handshake_hello: empty data!\n");
        return NULL;
    }

    int pos = TLSHDR_SIZE;
    int len;

    /* TLS record length */
    len = (data[3] << 8) +
        data[4] + TLSHDR_SIZE;
    data_len = std::min(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len){
        printf("parse_tls_handshake: incomplete packet! data len %u, packet len %u\n", data_len, len);
        return NULL;
    }

    // handshake
    if (pos + 1 > data_len) {
        return NULL;
    }
    if (data[pos] == 0x01 || data[pos] == 0x02) {
        return data + pos;
    }
    return NULL;    
}


unsigned char* find_pos_tls_handshake_hello_extensions(unsigned char* data, int data_len){
    
    if(!data){
        log_error("[Error]: find_pos_tls_handshake_hello_extensions: empty data!\n");
        return NULL;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    int pos = 38;
    int len;

     /* Session ID */
    if (pos + 1 > data_len)
        return NULL;
    len = data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if(data[0] == TLS_HANDSHAKE_CLIENT_HELLO){
        if (pos + 2 > data_len)
            return NULL;
        len = (data[pos] << 8) + data[pos + 1];
        pos += 2 + len;
    }
    else {
        pos += 2;
    }

    /* Compression Methods */
    if (pos + 1 > data_len)
        return NULL;
    len = data[pos];
    pos += 1 + len;

    if (pos == data_len) {
        printf("Received client hello without extensions");
        return NULL;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return NULL;
    len = (data[pos] << 8) + data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return NULL;
    return data + pos;
}


unsigned char* find_pos_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len) {

    if(!data){
        log_error("[Error]: find_pos_tls_handshake_hello_extension_max_frag_len: empty data!\n");
        return NULL;
    }
    
    int pos = 0;
    int len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = (data[pos + 2] << 8) +
            data[pos + 3];

        /* Check if it's a max_frag_len */
        if (data[pos] == 0x00 && data[pos + 1] == 0x01) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return NULL;
            return data + pos + 4;
        }
        pos += 4 + len; /* Advance to the next extension header */
    }

    return NULL;
}


void set_tls_handshake_hello_extension_max_frag_len(unsigned char *extension, unsigned char dst){
	if(!extension){
		return;
	}
	extension[0] = 0x00;
	extension[1] = 0x01;
	extension[2] = 0x00;
	extension[3] = 0x01;
	extension[4] = dst;
}


void append_tls_handshake_hello_extension_max_frag_len(unsigned char *src, int src_len, unsigned char* dst){
    if(!src || !dst)
        return;

    unsigned char max_frag_len[6] = {0};
    set_tls_handshake_hello_extension_max_frag_len(max_frag_len, 1);
    memcpy(dst, src, src_len);
    memcpy(dst+src_len, max_frag_len, 5);
}










// int set_tls_handshake_hello_extension_max_frag_len(uint8_t *data, int data_len) {
//     int pos = 0; 
//     int len;

//     unsigned char value = data[pos];
//     printf("parse_max_frag_len_extension: value %d\n", value);
// }


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





// // int process_tls_payload(bool in_coming, unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){
// int find_pos_tls_handshake(unsigned char* tcp_payload, int tcp_payload_len){
//     int read_bytes = 0;

//     while(read_bytes < tcp_payload_len){
//         unsigned char* remain_payload = tcp_payload+read_bytes;
//         struct mytlshdr *tlshdr = (struct mytlshdr*)(remain_payload);
//         int tlshdr_len = htons(tlshdr->length);

//         // if(tlshdr->version == 0x0303){ //CLient hello has 0x0301
//             switch (tlshdr->type){
//                 case TLS_TYPE_HANDSHAKE:
//                 {
//                     return read_bytes;
//                     // parse_tls_handshake(remain_payload, payload_len - read_bytes);
//                 }

//                 case TLS_TYPE_CHANGE_CIPHER_SPEC:// what if an application data comes after 
//                 {
//                     return 0;
//                     break;
//                 }
//                 case TLS_TYPE_APPLICATION_DATA:
//                 {
//                     return 0;
//                     break;
//                 }
//                 default:
//                 {
//                     printf("Unknown type: %d letting through\n", tlshdr->type);
//                     return 0;
//                     break;
//                 }
//             }
//             read_bytes += tlshdr_len + TLSHDR_SIZE;
//         // }
//         // else
//         //     return 0;
//     }
// }


        // unsigned char* tls_hdsk = find_pos_tls_handshake(payload, payload_len);
        // if(tls_hdsk){
        //     unsigned char* tls_hdsk_hello = find_pos_tls_handshake_hello(tls_hdsk, payload_len);
        //     if(tls_hdsk_hello){
        //         if(!from_server){
        //             unsigned char* new_payload = (unsigned char*)malloc(payload_len+5);
        //             if(!new_payload){
        //                 printf("append_max_frag_len: malloc fails!\n");
        //             }
        //             else{
        //                 memset(new_payload, 0, payload_len + 5);
        //                 memcpy(new_payload, payload, payload_len);
        //                 set_tls_handshake_hello_extension_max_frag_len(new_payload+payload_len, 1);
        //                 send_ACK_payload(g_remote_ip, g_local_ip, g_remote_port, local_port, new_payload, payload_len+5, ack, seq, ntohs(tcphdr->th_win));
        //                 sprintf(log, "%s - sent_appended_max_frag_len packet. drop original packet.", log);        
        //                 verdict = -1;
        //             }
        //         }
        //     }
        // }
