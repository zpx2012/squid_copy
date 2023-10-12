#include "logging.h"
#include <bits/stdc++.h>

#include "interval.h"
#include "tls.h"
#include "get_server_key_single.h"

const int tls_debug = 0;
const int lock_debug = 0;
const int partial_decrypt = 1;

int print_hexdump(unsigned char* hexdump, int len){
    for(int i = 0; i < len; i++){
        printf("%02x ", hexdump[i]);
        if(i % 16 == 15)
            printf("\n");
    }
    printf("\n");
    // print_func("\n\n");
    return 0;
}


int insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint new_seq_start, unsigned char* new_data, int new_data_len){
    if(!&tls_rcvbuf || !new_data || !new_data_len){
        print_func("insert_to_rcvbuf: one of the argument is NULL. tls_rcvbuf %p, new_data %p, new_datalen %d.\n", &tls_rcvbuf, new_data, new_data_len);
    }
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


TLS_Crypto_Coder::TLS_Crypto_Coder(const EVP_CIPHER * ec, unsigned char* salt, unsigned char* key, unsigned int vs_rvs, unsigned short lp){
    this->evp_cipher = ec;
    
    memcpy(this->iv_salt, salt, 4);
    this->iv_salt[4] = 0;

    memcpy(this->write_key_buffer, key, 100);//100 to be modified
    this->write_key_buffer[99] = 0;

    this->key_obtained = true;

    this->version_rvs = vs_rvs;

    this->local_port = lp;
}


int TLS_Crypto_Coder::decrypt_record(uint64_t record_num, unsigned char* record_data, int record_len, unsigned char* plaintext){
    if(record_len <= 8 + TLSHDR_SIZE)
        return -1;        

    unsigned char* appdata = record_data + TLSHDR_SIZE;
    int appdata_len = record_len - TLSHDR_SIZE;

    unsigned char* ciphertext = appdata + 8;
    int ciphertext_len = appdata_len - 8 - 16;

    unsigned char iv[13] = {0};
    memcpy(iv, iv_salt, 4);
    
    unsigned long long iv_num = *((unsigned long long*)appdata); //bug: iv could be break into two packets and the iv got from this will be wrong 
    if(iv_num){
        memcpy(iv+4, appdata, 8);
        if(tls_debug > 0){
            print_func("decrypt_record: Record No.%lu, iv_num exists ", record_num);
            print_hexdump(appdata, 8);
        }
    }
    else{
        // unsigned long long iv_num = htobe64(*((unsigned long long*)iv_xplct_ini));
        iv_num = htobe64(iv_num_ini+record_num-1);
        memcpy(iv+4, &iv_num, 8);
        if(tls_debug > 0)
            print_func("decrypt_record: Record No.%lu, iv_num not exists, calculated iv_num is %lx\n", record_num, htobe64(iv_num));
    }
    iv[12] = 0;

    unsigned char aad[14] = {0};
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


int TLS_Crypto_Coder::generate_record(uint64_t record_num, unsigned char* plaintext, int len, unsigned char* record_buf){
    //len > record_size?
    
    record_buf[0] = TLS_TYPE_APPLICATION_DATA;
    *((uint16_t*)(record_buf+1)) = version_rvs;
    *((uint16_t*)(record_buf+3)) = ntohs(len+8+16);

    unsigned char iv[13];
    memcpy(iv, iv_salt, 4);
    // unsigned long long iv_num = htobe64(*((unsigned long long*)iv_xplct_ini));
    unsigned long long iv_num = htobe64(iv_num_ini+record_num-1);
    memcpy(iv+4, &iv_num, 8);
    iv[12] = 0;
    // print_func("IV ini:");
    // print_hexdump(iv_xplct_ini, 8);
    // print_func("IV:");
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


int TLS_Crypto_Coder::get_aad(uint64_t record_num, int len, unsigned char* aad){
    record_num = htobe64(record_num);
    memcpy(aad, &record_num, 8);
    aad[8] = TLS_TYPE_APPLICATION_DATA;
    *((uint16_t*)(aad+9)) = version_rvs;
    *((uint16_t*)(aad+11)) = ntohs(len);
    aad[13] = 0;
    return 0;
}


void TLS_Crypto_Coder::set_iv_explicit_init(unsigned char* iv_ex){
    memcpy(this->iv_xplct_ini, iv_ex, 8);
    this->iv_xplct_ini[8] = 0;
    if(tls_debug > 2){
        print_func("set_iv_explicit_init: iv_xplct_ini ");
        print_hexdump(iv_ex, 8);
    }
    iv_num_ini = htobe64(*((unsigned long long*)iv_xplct_ini));
    iv_xplct_ini_set = true;
}


int TLS_Crypto_Coder::get_record_num_from_iv_explicit(unsigned char* iv_ex){
    unsigned long long iv_ex_int = htobe64(*((unsigned long long*)iv_ex));
    if(tls_debug > 2){
        print_func("get_record_num_from_iv_ex: iv_ex ");
        print_hexdump(iv_ex, 8);
        print_func("iv_ex_ini ");
        print_hexdump(iv_xplct_ini, 8);
        print_func("iv_num_ini %llu\n", iv_num_ini);
    }
    if(iv_ex_int < iv_num_ini)
        return -1;
    return iv_ex_int - iv_num_ini + 1;
}

int TLS_Encrypted_Record_Reassembler::insert_to_record_fragment(uint seq, unsigned char* ciphertext, int ciphertext_len){
    return insert_to_rcvbuf(tls_ciphertext_rcvbuf, seq, ciphertext, ciphertext_len);
}

int TLS_Encrypted_Record_Reassembler::merge_record_fragment(){
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

int TLS_Encrypted_Record_Reassembler::merge_two_record_fragment(struct record_fragment* frag, unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len){
    frag->data = merge_two_data(first_data, first_data_len, second_data, second_data_len);
    frag->data_len = first_data_len + second_data_len;
    return 0;
}

unsigned char* merge_two_data(unsigned char* first_data, int first_data_len, unsigned char* second_data, int second_data_len){
    unsigned char* new_data = (unsigned char*)malloc(first_data_len+second_data_len);
    if(!new_data){
        print_func("merge_two_data:370: malloc(%d) failed!\n", first_data_len+second_data_len);
        return first_data;
    }
    memcpy(new_data, first_data, first_data_len);
    memcpy(new_data+first_data_len, second_data, second_data_len);
    free(first_data);
    free(second_data);
    return new_data;
}


int TLS_Encrypted_Record_Reassembler::decrypt_record_fragment(std::map<uint, struct record_fragment> &plaintext_rcvbuf){
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

int TLS_Encrypted_Record_Reassembler::decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    int decrypt_start_local = (seq/record_full_size*record_full_size+1) - seq;
    int decrypt_end_local;
    if(decrypt_start_local < 0){
        // print_func("decrypt_one_payload: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d), add to %d\n", decrypt_start_local, seq_data_start, seq, payload, payload_len, decrypt_start_local+record_full_size);
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
            print_func("decrypt_record_fragment: header not found\n\n");
            print_func("After:\n");
            print_hexdump(payload, payload_len);
            print_func("New header: \n");
            print_hexdump(payload+decrypt_end_local, payload_len-decrypt_end_local);
            exit(-1);
        }
        else {
            if(tlshdr_len != record_full_size-TLSHDR_SIZE){
                print_func("tlshdr length %d != %lu !\n", tlshdr_len, record_full_size-TLSHDR_SIZE);
            }
            unsigned char plaintext[MAX_FRAG_LEN+1] = {0};//
            int plaintext_len = crypto_coder->decrypt_record(seq+decrypt_end_local, payload+decrypt_end_local, tlshdr_len + TLSHDR_SIZE, plaintext);
            if(plaintext_len > 0){
                if(tls_debug > 1){
                    print_func("decrypt_one_payload: ciphertext_seq %u\nCiphertext:\n", seq+decrypt_end_local);
                    print_hexdump(payload+decrypt_end_local, record_full_size);
                    print_func("Plaintext:\n");
                    print_hexdump(plaintext, plaintext_len);
                }
                insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, plaintext, plaintext_len);
            }
            // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, payload+decrypt_end_local, record_full_size);
        }
    }
    decrypt_start = decrypt_start_local;
    decrypt_end = decrypt_end_local;
    return 0;
}

void TLS_Encrypted_Record_Reassembler::lock(){
    if(tls_debug && lock_debug)
        print_func("TLS_Encrypted_Record_Reassembler: try lock\n");
    pthread_mutex_lock(&mutex);
}

void TLS_Encrypted_Record_Reassembler::unlock(){
    if(tls_debug && lock_debug)
        print_func("TLS_Encrypted_Record_Reassembler: try unlock\n");
    pthread_mutex_unlock(&mutex);
}



TLS_Decrypted_Record_Reassembler::TLS_Decrypted_Record_Reassembler(int rs, int size){
    plntxt_buffer = new Reassembler(0, REASSEM_TCP);
    record_num = rs;
    expected_size = size;
    tags.clear();
    if(tls_debug > 0)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d created\n", this, rs);
}


TLS_Decrypted_Record_Reassembler:: ~TLS_Decrypted_Record_Reassembler(){
    lock();
    cleanup();
    unlock();
}


void TLS_Decrypted_Record_Reassembler::cleanup(){
    // const std::lock_guard<std::mutex> lock(mutex);
    // lock();
    if (tls_debug)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, cleanup\n", this, record_num);
    
    if(!tags.empty()){
        for(auto it = tags.begin(); it != tags.end(); it++){
            delete it->second;
            // tags.erase(it++);
        }
    }
    tags.clear();
    if(plntxt_buffer){
        delete plntxt_buffer;
        plntxt_buffer = nullptr;
    }
    // unlock();
}


void TLS_Decrypted_Record_Reassembler::lock(){
    if(tls_debug && lock_debug)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, try lock\n", this, record_num);
    pthread_mutex_lock(&mutex);
}

void TLS_Decrypted_Record_Reassembler::unlock(){
    pthread_mutex_unlock(&mutex);
    if(tls_debug && lock_debug)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, try unlock\n", this, record_num);
}

int TLS_Decrypted_Record_Reassembler::insert_plaintext(TLS_Crypto_Coder* cypto_coder, uint seq, u_char* data, int data_len){
	// const std::lock_guard<std::mutex> lock(mutex);
    if(tls_debug > 0)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, insert plaintext,  plaintext_len %d\n", this, record_num, seq, data_len);
    lock();
    if(plntxt_buffer){
        plntxt_buffer->NewBlock(seq, data_len, data);
        if (!tags.count(cypto_coder)){
            tags[cypto_coder] = new Reassembler(0, REASSEM_UNKNOWN);       
        }        
    }
    unlock();
    return 0;
}

int TLS_Decrypted_Record_Reassembler::insert_tag(TLS_Crypto_Coder* cypto_coder, uint offset, u_char* tag, int tag_len){
	// const std::lock_guard<std::mutex> lock(mutex);
    if(tag_len < 0 || tag_len > 16){
        if(tls_debug > 0)
            print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, insert tag, offset %u, tag_len %d, invalid tag_len! return -1.\n", this, record_num, offset, tag_len);
        return -1;
    }
    if(tls_debug > 0)
        print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, insert tag, offset %u, tag_len %d\n", this, record_num, offset, tag_len);
    lock();
    if(plntxt_buffer){
        if (!tags.count(cypto_coder)){
            tags[cypto_coder] = new Reassembler(0, REASSEM_UNKNOWN);       
        }
        tags[cypto_coder]->NewBlock(offset, tag_len, tag);
    }
    unlock();
    return 0;
}


// if complete, return equal（0） or false(0); otherwise, -1
int TLS_Decrypted_Record_Reassembler::check_complete(u_char* buf, int buf_len, u_short* &participated_ports, int &participated_ports_len){
	// const std::lock_guard<std::mutex> lock(mutex);
    // print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, check_complete\n", this, record_num);
    lock();
    int verdict = -1;
    u_char* tag = nullptr;
    if(plntxt_buffer && plntxt_buffer->TotalSize() == expected_size){
        for (auto it = tags.begin(); it != tags.end(); it++){
            if(it->second->TotalSize() == 16){
                if(tls_debug > 0)
                    print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, plaintext is complete,found tag in coder %p\n", this, record_num, it->first);
                get_complete_plaintext(buf, buf_len);
                tag = (u_char*)malloc(16);
                int tag_len = it->second->InOrderStrs(tag, 16);
                if(tag_len != 16){
                    if(tls_debug > 0)
                        print_func("TLS_Decrypted_Record_Reassembler(%p):No.%d, inserted: tag_len is %d\n", this, record_num, tag_len);
                    continue;
                }
                verdict = verify(buf, buf_len, it->first, tag);
                if(tls_debug > 0)
                break;
            }
        }
    }
    if(verdict > 0){
        if(tls_debug > 0)
            print_func("TLS_Decrypted_Record_Reassembler(%p):No.%d, inserted: plaintext is complete, tag verified. run cleanup\n", this, record_num);

        participated_ports_len = tags.size();
        participated_ports = new u_short[participated_ports_len];
        int i = 0;
        for(auto it = tags.begin(); it != tags.end(); it++)
            participated_ports[i++] = it->first->local_port;
        
    }
    if(verdict >= 0)
        cleanup();
    
    if(tag)
        free(tag);

    unlock();
    return verdict;
}

int TLS_Decrypted_Record_Reassembler::get_complete_plaintext(u_char* buf, int es){
    int buf_len = plntxt_buffer->InOrderStrs(buf, es);
    if (buf_len != es){
        print_func("TLS_Decrypted_Record_Reassembler::get_complete_plaintext: Not complete! copied_len %d, expected size %d\n", buf_len, expected_size);
        return -1;
    }

    return buf_len;
}

bool TLS_Decrypted_Record_Reassembler::verify(u_char* plntxt, int plntxt_len, TLS_Crypto_Coder* crypto_coder, u_char* tag){
    //encrypt it to generate ciphertext
    u_char* ciphertext = new u_char[plntxt_len+TLSHDR_SIZE+8+16+1];
    int ciphertext_len = crypto_coder->generate_record(record_num, plntxt, plntxt_len, ciphertext);
    //compare the tag to verify
    bool legit = false;
    if(ciphertext_len){
        ciphertext[ciphertext_len] = 0;
        u_char* regenerated_tag = ciphertext + ciphertext_len - 16;
        int ret = strncmp((char *)(tag), (char *)regenerated_tag, 16);
        legit = !ret;
        if(tls_debug > 0){
            print_hexdump(tag, 16);
            print_hexdump(regenerated_tag, 16);
            print_func("strncmp: %d\n", ret);
        }
    }
    delete [] ciphertext;
    return legit;
}

TLS_Decrypted_Records_Map::~TLS_Decrypted_Records_Map() {
    // lock();
    // for(size_t i = 0; i < 42750; i++)
    //     delete decrypted_record_reassembler_map[i];
    // delete [] decrypted_record_reassembler_map;
    // unlock();
    // print_func("enter ~TLS_Decrypted_Records_Map\n");
    lock();    
    for(auto it = decrypted_record_reassembler_map.begin(); it != decrypted_record_reassembler_map.end(); ){
        // print_func("delete TLS_Decrypted_Records_Map(%p) for record_num(%d)\n", it->second, it->first);
        delete it->second;
        decrypted_record_reassembler_map.erase(it++);
    }
    unlock();  

}


int TLS_Decrypted_Records_Map::inserted(int record_num, TLS_Decrypted_Record_Reassembler* tls_decrypted_record, u_char* &return_str, u_short* &return_ports, int &return_ports_len){

    if(!tls_decrypted_record)
        return -1;

    //Found the complete tag
    int buf_len = tls_decrypted_record->expected_size;
    u_char *buf = new u_char[buf_len+1];
    int ret = tls_decrypted_record->check_complete(buf, buf_len, return_ports, return_ports_len);
    if(ret < 0)
    {
        if(buf)
            delete [] buf;
        return -1;
    }
    if(tls_debug > 0){
        if(ret == 1)
            print_func("inserted: No.%d. Tag verified.\n", record_num);
        else{
            print_func("inserted: No.%d. Tag verification failed.\n", record_num);
            if(tls_debug > 2){
                print_func("Plaintext:\n");
                print_hexdump(buf, buf_len);
            }
        }
    }

    int ciphertext_len = 0;
    if(ret == 1){
        u_char* ciphertext = new u_char[buf_len+TLSHDR_SIZE+8+16+1];
        ciphertext_len = main_subconn_cypto_coder->generate_record(record_num, buf, buf_len, ciphertext);
        if(ciphertext_len > 0){
            return_str = ciphertext;
            if(tls_debug > 0){
                print_func("inserted: No.%d. Re-encrypted. assign return_str to %p\n", record_num, ciphertext);
            }
        }
    }
    delete [] buf;

    lock();
    if(ret == 1)
        successful++;
    else
        failed++;
    unlock();
    return ciphertext_len;
}


void TLS_Decrypted_Records_Map::print_result(){
    int incompleted_counter = 0;
    print_func("Print TLS_Decrypted_Record_Reassembler: ");
    for(auto it = decrypted_record_reassembler_map.begin(); it != decrypted_record_reassembler_map.end(); it++){
        // if(it->second == nullptr){
        //     print_func("%d:1, ", it->first);
        //     completed_counter++;
        // }
        if(it->second){
            incompleted_counter++;
            print_func("%d:%lu(%d), ", it->first, it->second->plntxt_buffer->TotalSize(), it->second->expected_size);
        }
    }
    print_func("\nSuccessful, Failed, Incompleted/Total: %d, %d, %lu/%lu.\n", successful, failed, decrypted_record_reassembler_map.size() - successful - failed, decrypted_record_reassembler_map.size());
}


void TLS_Decrypted_Records_Map::lock(){
    if(tls_debug && lock_debug)
        print_func("TLS_Decrypted_Records_Map: try lock\n");
    pthread_mutex_lock(&mutex);
}

void TLS_Decrypted_Records_Map::unlock(){
    pthread_mutex_unlock(&mutex);
    if(tls_debug && lock_debug)
        print_func("TLS_Decrypted_Records_Map: try unlock\n");
}

// int TLS_Decrypted_Records_Map::insert_plaintext(int record_num, uint seq, u_char* data, int data_len, u_char* &return_str){
//     if (!decrypted_record_reassembler_map.count(record_num)){
//         lock();
//         if (!decrypted_record_reassembler_map.count(record_num)){
//             decrypted_record_reassembler_map[record_num] = new TLS_Decrypted_Record_Reassembler(MAX_FRAG_LEN);
//         }
//         unlock();
//     }
//     decrypted_record_reassembler_map[record_num]->insert_plaintext(seq, data, data_len);
//     if(tls_debug > 0){
//         print_func("insert_plaintext: No.%d, seq %u, len %d\n", record_num, seq, data_len);
//     }
//     return 0;
// }

int TLS_Decrypted_Records_Map::insert(int record_num, int record_size, TLS_Crypto_Coder* crypto_coder, uint seq, u_char* data, int data_len, uint tag_offset, u_char* tag, int tag_len, u_char* &return_str, u_short* &return_ports, int& return_ports_len){
    if (!decrypted_record_reassembler_map.count(record_num)){
        lock();
        if (!decrypted_record_reassembler_map.count(record_num)){
            mutex_map[record_num] = PTHREAD_MUTEX_INITIALIZER;
            decrypted_record_reassembler_map[record_num] = new TLS_Decrypted_Record_Reassembler(record_num, MAX_FRAG_LEN);
            // print_func("new TLS_Decrypted_Record_Reassembler(%p) for record_num(%d)\n", decrypted_record_reassembler_map[record_num], record_num);
        }

        // if(tls_decrypted_record){
        //     if(tls_debug > 0)
        //         print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, get tls_decrypted_record(%p), record_num %d, plntxt_buffer(%p)\n", tls_decrypted_record, record_num, seq, tls_decrypted_record, tls_decrypted_record->record_num, tls_decrypted_record->plntxt_buffer);

        //     if(!tls_decrypted_record->plntxt_buffer){
        //         // if(tls_debug > 0)
        //         //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, try lock to delete tls_record\n", tls_decrypted_record, record_num, seq);
        //         // pthread_mutex_lock(mutex_record);
        //         // if(tls_debug > 0)
        //         //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, gain lock. plntxt_buffer empty, delete it, call cleanup.\n", tls_decrypted_record, record_num, seq);

        //         // delete tls_decrypted_record;
        //         // pthread_mutex_unlock(mutex_record);
        //         // if(tls_debug > 0)
        //         //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, unlock. Set map entry to nullptr\n", tls_decrypted_record, record_num, seq);

        //         decrypted_record_reassembler_map[record_num] = nullptr;
        //         unlock();
        //         return -1;
        //     }
        // }
        unlock();
    }

    TLS_Decrypted_Record_Reassembler* tls_decrypted_record = decrypted_record_reassembler_map[record_num];
    pthread_mutex_t* mutex_record = &mutex_map[record_num];


    if(tls_decrypted_record && tls_decrypted_record->record_num == record_num){
        // if(tls_debug > 0)
        //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, try lock to insert\n", tls_decrypted_record, record_num, seq);
        // pthread_mutex_lock(mutex_record);
        // if(tls_debug > 0)
        //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, gain lock, inner_recordnum %d, plntxt_buffer(%p)\n", tls_decrypted_record, record_num, seq, tls_decrypted_record->record_num, tls_decrypted_record->plntxt_buffer);
        // tls_decrypted_record->lock();

        int ret;
        if(tls_decrypted_record->plntxt_buffer && tls_decrypted_record->record_num == record_num){// when tls_decrypted_record is deleted, this pointer will point to any address, plntxt_buffer will not be null, but record_num will not be correct either 

            if(record_size){
                tls_decrypted_record->expected_size = record_size;
            }

            if(data && data_len){
                // pthread_mutex_lock(mutex_record);
                if(tls_decrypted_record->plntxt_buffer && tls_decrypted_record->record_num == record_num){// when tls_decrypted_record is deleted, this pointer will point to any address, plntxt_buffer will not be null, but record_num will not be correct either 
                    tls_decrypted_record->insert_plaintext(crypto_coder, seq, data, data_len);
                    if(tls_debug > 0)
                        print_func("TLS_Decrypted_Record_Map(%p): No.%d, seq %u, insert_plaintext len %d\n", 
                                this, record_num, seq, data_len);
                }
                // pthread_mutex_unlock(mutex_record);
            }

            if(tag && tag_len){
                // pthread_mutex_lock(mutex_record);
                if(tls_decrypted_record->plntxt_buffer && tls_decrypted_record->record_num == record_num){// when tls_decrypted_record is deleted, this pointer will point to any address, plntxt_buffer will not be null, but record_num will not be correct either 
                    tls_decrypted_record->insert_tag(crypto_coder, tag_offset, tag, tag_len);
                    if(tls_debug > 0){
                        print_func("TLS_Decrypted_Record_Map(%p): No.%d, seq %u, insert_tag: offset %u, len %d, ", this, record_num, seq, tag_offset, tag_len);
                        print_hexdump(tag, tag_len);
                    }
                }
                // pthread_mutex_unlock(mutex_record);
            }

            // pthread_mutex_lock(mutex_record);
            if(tls_decrypted_record->plntxt_buffer && tls_decrypted_record->record_num == record_num){// when tls_decrypted_record is deleted, this pointer will point to any address, plntxt_buffer will not be null, but record_num will not be correct either 
                ret = inserted(record_num, tls_decrypted_record, return_str, return_ports, return_ports_len);
                // if(ret >= 0)
                //     delete tls_decrypted_record;
            }
            // pthread_mutex_unlock(mutex_record);
        }
        // tls_decrypted_record->unlock();
        // pthread_mutex_unlock(mutex_record);
        // if(tls_debug > 0)
        //     print_func("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, unlock\n", tls_decrypted_record, record_num, seq);

        if(ret >= 0){
            // lock();
            // print_func("delete TLS_Decrypted_Records_Map(%p) for record_num(%d)\n", tls_decrypted_record, record_num);
            delete decrypted_record_reassembler_map[record_num];
            decrypted_record_reassembler_map[record_num] = nullptr;
            // decrypted_record_reassembler_map.erase(record_num);
            // unlock();
        }

        return ret;
    }
    return -1;
}

TLS_Record_Number_Seq_Map::TLS_Record_Number_Seq_Map(){
    next_record_start_seq = 1;
    first_max_frag_seq = last_piece_start_seq = 0;
    record_num_count = 0;
    tls_seq_map.clear();
}

TLS_Record_Number_Seq_Map::~TLS_Record_Number_Seq_Map(){
    lock();
    for(auto it = tls_seq_map.begin(); it != tls_seq_map.end(); ){
        delete it->second;
        tls_seq_map.erase(it++);
    }
    unlock();  
} 

TLS_Record_Seq_Info* TLS_Record_Number_Seq_Map::insert_nolock(uint start_seq, int record_num, int record_size_with_header){
    // if(start_seq == next_record_start_seq){
        TLS_Record_Seq_Info* seq_info = NULL;
        if(!tls_seq_map.count(start_seq)){
            // if(record_size_with_header == MAX_FULL_GCM_RECORD_LEN){
            //     auto it = tls_seq_map.upper_bound(start_seq);
            //     if(it != tls_seq_map.begin()){
            //         TLS_Record_Seq_Info* seq_info = std::prev(it)->second;
            //         if(seq_info && seq_info->seq <= start_seq){
            //             if(seq_info->upper_seq < start_seq + record_size_with_header){
            //                 seq_info->upper_seq = start_seq + record_size_with_header;
            //                 if(tls_debug > 0)
            //                     print_func("S%d: TLS_Record_Number_Seq_Map: MAX_FULL_GCM_RECORD_LEN, update upper_seq to %u\n", local_port, seq_info->upper_seq);
            //             }
            //             return 0;
            //         }
            //     }
            // }

            seq_info = new TLS_Record_Seq_Info(record_num, record_size_with_header, start_seq, start_seq+record_size_with_header);
            tls_seq_map[start_seq] = seq_info;
            next_record_start_seq = start_seq + record_size_with_header;
            if(tls_debug == -1)
                print_func("S%d: TLS_Record_Number_Seq_Map: insert No.%d, seq %u, len %d\n", local_port, record_num, start_seq, record_size_with_header);
        }
        else{
            seq_info = tls_seq_map[start_seq];
            if(!seq_info->record_size_with_header){
                if(tls_debug == -1)
                    print_func("S%d: TLS_Record_Number_Seq_Map::set_size: found seq %u, No.%d, update length to %d\n", local_port, start_seq, seq_info->record_num, record_size_with_header);

                if(seq_info->record_num != record_num)
                    if(tls_debug == -1)
                        print_func("S%d: TLS_Record_Number_Seq_Map::set_size: found seq %u, No.%d != given record_num %d\n", local_port, start_seq, seq_info->record_num, record_size_with_header);

                seq_info->record_num = record_num;
                seq_info->record_size_with_header = record_size_with_header;
                seq_info->upper_seq = start_seq + record_size_with_header;
            }
        }

        uint upper_seq = start_seq + record_size_with_header;
        if(!tls_seq_map.count(upper_seq)){ // && record_size_with_header != MAX_FULL_GCM_RECORD_LEN
            tls_seq_map[upper_seq] = new TLS_Record_Seq_Info(record_num+1, 0, upper_seq, upper_seq);
            if(tls_debug == -1)
                print_func("S%d: TLS_Record_Number_Seq_Map: insert No.%d, seq %u, len %d\n", local_port, record_num+1, upper_seq, 0);
        }

    // }
    // else{
    //     if(tls_debug > 0)
    //         print_func("S%d: TLS_Record_Number_Seq_Map: seq %u != next_record_start_seq %d\n", local_port, start_seq, next_record_start_seq);

    // }
    return seq_info;
}

TLS_Record_Seq_Info* TLS_Record_Number_Seq_Map::insert(uint start_seq, int record_num, int record_size_with_header){
    TLS_Record_Seq_Info* ret = NULL;
    lock();
    ret = insert_nolock(start_seq, record_num, record_size_with_header);
    unlock();
    return ret;
}


TLS_Record_Seq_Info* TLS_Record_Number_Seq_Map::check_if_tlshdr(uint seq, unsigned char* payload, int payload_len, TLS_Crypto_Coder* crypto_coder){
    struct mytlshdr* tlshdr = (struct mytlshdr*)payload;
    if(tlshdr->version == 0x0303 && tlshdr->type == TLS_TYPE_APPLICATION_DATA){
        int cur_record_size = htons(tlshdr->length) + TLSHDR_SIZE;
        int record_num = crypto_coder->get_record_num_from_iv_explicit(payload + TLSHDR_SIZE);
        // print_func("S%d: check_if_tlshdr: found record %d, at seq %d, record_len %d\n", local_port, record_num, seq, cur_record_size);
        return insert(seq, record_num, cur_record_size);        
    }
    return NULL;
}


TLS_Record_Seq_Info* TLS_Record_Number_Seq_Map::find_record_seq_info(uint seq, unsigned char* payload, int payload_len, TLS_Crypto_Coder* crypto_coder){
    TLS_Record_Seq_Info* ret_info = check_if_tlshdr(seq, payload, payload_len, crypto_coder);
    if(ret_info)
        return ret_info;

    ret_info = get_record_seq_info(seq);
    if(ret_info && ret_info->seq > 0)
        return ret_info;

    for(int i = 0; i < payload_len - TLSHDR_SIZE; i++){
        if((ret_info = check_if_tlshdr(seq+i, payload+i, payload_len-i, crypto_coder)))
            return ret_info;
    }

    return ret_info;
    
// if(tls_debug == -1)
//             print_func("S%d: TLS_Record_Number_Seq_Map: seq %u is not tlshdr\n", local_port, seq);
//         return -1;
}

int TLS_Record_Number_Seq_Map::set_size(uint start_seq, int record_size_with_header) {
    // if(record_size_with_header == MAX_FULL_GCM_RECORD_LEN){
    //     if (first_max_frag_seq == 0){        
    //         lock();
    //         if (first_max_frag_seq == 0){
    //             first_max_frag_seq = start_seq;
    //             if(tls_debug > 0)
    //                 print_func("S%d: TLS_Record_Number_Seq_Map::set_size: set first_max_frag_seq to %u\n", local_port, start_seq);
    //         }
    //         unlock();
    //     }
    //     return -1;
    // }
    
    // lock();
    // if(!tls_seq_map.count(start_seq)){
    //     if(tls_debug > 0){
    //         print_func("S%d: TLS_Record_Number_Seq_Map::set_size: seq %u not found, first_max_frag_seq %d\n", local_port, start_seq, first_max_frag_seq);
    //         for (const auto& x : tls_seq_map)
    //             print_func("S%d: start_seq %u, No.%d, length %d\n", local_port, x.first, x.second->record_num, x.second->record_size_with_header); 
    //     }
    //     if(first_max_frag_seq){ 
    //         if(start_seq > first_max_frag_seq){//Final piece
    //             last_piece_start_seq = start_seq;
    //             tls_seq_map[start_seq] = new TLS_Record_Seq_Info(get_record_num(start_seq), record_size_with_header, start_seq, start_seq+record_size_with_header);
    //             if(tls_debug > 0)
    //                 print_func("S%d: TLS_Record_Number_Seq_Map::set_size: seq %u, set the final piece length to %d\n", local_port, start_seq, record_size_with_header);
    //         }
    //     }
    //     else{
    //         //check last segment length is 0
    //         auto it = tls_seq_map.upper_bound(start_seq);
    //         if(it == tls_seq_map.begin()){
    //             print_func("S%d: TLS_Record_Number_Seq_Map::set_size: error! previous record not found!\n", local_port);
    //         }
    //         else{
    //             TLS_Record_Seq_Info* seq_info = std::prev(it)->second;
    //             if(!seq_info->record_size_with_header){
    //                 if(tls_debug > 0)
    //                     print_func("S%d: TLS_Record_Number_Seq_Map::set_size: last segment(%u, No.%d, %d) is lost, insert new piece(%u, No.%d, %d)\n", 
    //                                 local_port, seq_info->seq, seq_info->record_num, seq_info->record_size_with_header, start_seq, seq_info->record_num+1, record_size_with_header);
    //                 next_record_start_seq = start_seq;
    //                 insert_nolock(start_seq, record_size_with_header);
    //                 // insert_nolock(start_seq + record_size_with_header, 0);
    //             }
    //         }
    //     }
    // }
    // else{
    //     TLS_Record_Seq_Info* seq_info = tls_seq_map[start_seq];
    //     if(!seq_info->record_size_with_header){
    //         if(tls_debug > 0)
    //             print_func("S%d: TLS_Record_Number_Seq_Map::set_size: found seq %u, No.%d, update length to %d\n", local_port, start_seq, seq_info->record_num, record_size_with_header);

    //         seq_info->record_size_with_header = record_size_with_header;
    //         seq_info->upper_seq = start_seq + record_size_with_header;
    //     }
    //     else{
    //         if(tls_debug > 0)
    //             print_func("S%d: TLS_Record_Number_Seq_Map::set_size: found seq %u, No.%d, length is %d\n", local_port, start_seq, seq_info->record_num, seq_info->record_size_with_header);
    //     }
    //     if(start_seq == next_record_start_seq){
    //         next_record_start_seq = seq_info->upper_seq;
    //         record_num_count++;
    //     }
    // }
    // unlock();
    return 0;
}

TLS_Record_Seq_Info* TLS_Record_Number_Seq_Map::get_record_seq_info(uint seq){
    if(tls_debug == -1)
        print_func("S%d: TLS_Record_Number_Seq_Map: %p", local_port, this);

    TLS_Record_Seq_Info* seq_info = NULL;
    lock();
    if(!tls_seq_map.empty()){
        auto it = tls_seq_map.upper_bound(seq);
        if(it != tls_seq_map.begin())
            seq_info = std::prev(it)->second;
    }
    unlock();
    if(!seq_info)
        return NULL;

    if(seq_info && seq_info->record_size_with_header == 0)
        return NULL;

    if(tls_debug > 0 && seq_info) // 
        print_func("S%d: TLS_Record_Number_Seq_Map: get_record_seq_info: seq %u, found seq_info No.%d[%u, %u, %u]\n", local_port, seq, seq_info->record_num, seq_info->seq, seq_info->record_size_with_header, seq_info->upper_seq);


    // if(seq_info && seq_info->seq <= seq)//Later part comes first?
    // {
        // if (seq < seq_info->upper_seq){
        //     print_func("TLS_Record_Number_Seq_Map: get_record_seq_info: return NULL");
        //     return NULL;
        // }

        // return_info->record_num = seq_info->record_num;
        // return_info->seq = seq_info->seq;
        // return_info->upper_seq = seq_info->upper_seq;
        // return_info->record_size_with_header = seq_info->record_size_with_header;

        // if(seq_info->record_size_with_header == MAX_FULL_GCM_RECORD_LEN){
        //     int record_num_since_maxfraglen = (seq - return_info->seq) / MAX_FULL_GCM_RECORD_LEN;
        //     // return_info->record_size_with_header = MAX_FULL_GCM_RECORD_LEN;
        //     return_info->seq += record_num_since_maxfraglen * return_info->record_size_with_header;
        //     return_info->upper_seq = return_info->seq + return_info->record_size_with_header;
        //     return_info->record_num += record_num_since_maxfraglen;
        //     if(tls_debug > 0)
        //         print_func("S%d: TLS_Record_Number_Seq_Map: get_record_seq_info: length == MAX_FULL_LEN, No.%d[%u, %u, %u].\n", local_port, return_info->record_num, return_info->seq, return_info->record_size_with_header, return_info->upper_seq);
        //     return 0;
        // }

    // }
    return seq_info;
}

// int TLS_Record_Number_Seq_Map::get_record_seq_info_old(uint seq, TLS_Record_Seq_Info* return_info){
//     if(tls_seq_map.empty())
//         return -1;

//     if(first_max_frag_seq == 0 || (seq < first_max_frag_seq) || (last_piece_start_seq > 0 && seq > last_piece_start_seq)){
//         auto it = tls_seq_map.upper_bound(seq);
//         // if(tls_debug > 0)
//             // print_func("S%d: TLS_Record_Number_Seq_Map: seq %u, found upper_bound [%u, %d, %d]\n", local_port, seq, it->second->seq, it->second->record_num, it->second->record_size_with_header);
//         if(it == tls_seq_map.begin())
//             return -1;
//         TLS_Record_Seq_Info* seq_info = std::prev(it)->second;
//         if(seq_info && seq_info->seq <= seq && seq < seq_info->upper_seq)//Later part comes first?
//         {
//             return_info->record_num = seq_info->record_num;
//             return_info->seq = seq_info->seq;
//             return_info->upper_seq = seq_info->upper_seq;
//             return_info->record_size_with_header = seq_info->record_size_with_header;
//             return 0;
//         }
//     }
//     else{
//         int record_num_since_maxfraglen = (seq - first_max_frag_seq) / MAX_FULL_GCM_RECORD_LEN;
//         return_info->record_size_with_header = MAX_FULL_GCM_RECORD_LEN;
//         return_info->seq = first_max_frag_seq + record_num_since_maxfraglen * return_info->record_size_with_header;
//         return_info->upper_seq = return_info->seq + return_info->record_size_with_header;
//         return_info->record_num = record_num_count + record_num_since_maxfraglen + 1;
//         return 0;
//     }
//     return -1;
// }


int TLS_Record_Number_Seq_Map::get_record_num(uint seq){

    TLS_Record_Seq_Info* seq_info = get_record_seq_info(seq);
    if(seq_info)
        return seq_info->record_num;
    return -1;
}


void TLS_Record_Number_Seq_Map::print_record_seq_map(){
    print_func("S%d: ", local_port);
    for (const auto& x : tls_seq_map)
        print_func("[No.%d, %u, %d], ", x.second->record_num, x.first, x.second->record_size_with_header); 
    print_func("\n");
}


void TLS_Record_Number_Seq_Map::lock(){
    if(tls_debug && lock_debug)
        print_func("S%d: TLS_Record_Number_Seq_Map: try lock\n", local_port);
    pthread_mutex_lock(&mutex);
}

void TLS_Record_Number_Seq_Map::unlock(){
    if(tls_debug && lock_debug)
        print_func("S%d: TLS_Record_Number_Seq_Map: try unlock\n", local_port);
    pthread_mutex_unlock(&mutex);
}


//return verdict
// int process_incoming_tls_payload(bool in_coming, unsigned int seq_tls_data, unsigned char* payload, int payload_len, subconn_info* subconn, std::map<uint, struct record_fragment> &return_buffer){ // TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

//     if(!in_coming)
//         return -1;

//     struct mytlshdr *tlshdr = (struct mytlshdr*)(payload);
//     int tlshdr_len = htons(tlshdr->length);

//     if(tlshdr->version == subconn->crypto_coder->get_version_reversed()){
//         if(tlshdr->type == TLS_TYPE_APPLICATION_DATA && tlshdr_len > 8){
//             return process_incoming_tls_appdata(true, seq_tls_data, payload, payload_len, subconn, decrypted_records_map, return_buffer);
//         }
//         else{
//             print_func("Unknown type: %d or tlshdr_len %d <= 8\n", tlshdr->type, tlshdr_len);
//             return -1;
//         }
//     }
//     else{
//         return process_incoming_tls_appdata(false, seq_tls_data, payload, payload_len, subconn, decrypted_records_map, return_buffer);
//     }
// }


int Optimack::process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, subconn_info* subconn, std::map<uint, struct record_fragment> &return_buffer){ // TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

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


    // int decrypt_start = 0, decrypt_end = 0;
    if(seq == 1){
        print_func("S%d-%d: set iv_explicit_ini ", subconn->id, subconn->local_port);
        print_hexdump(payload+TLSHDR_SIZE, 8);
        subconn->crypto_coder->set_iv_explicit_init(payload+TLSHDR_SIZE);

        struct mytlshdr *tlshdr = (struct mytlshdr*)(payload);
        int record_size = htons(tlshdr->length) + TLSHDR_SIZE;

        if(tlshdr->version == subconn->crypto_coder->get_version_reversed()){
            tls_record_seq_map->set_localport(subconn->local_port);
            tls_record_seq_map->insert(1, 1, record_size);
        }
        else{
            print_func("S%d-%d: set size failed, version %x, stored version %x\n", subconn->id, subconn->local_port, tlshdr->version, subconn->crypto_coder->get_version_reversed());
        }
    }
    
    int count = 0;
    if(!subconn->crypto_coder->get_iv_xplct_ini_set() || tls_record_seq_map->empty()){
        print_func("S%d-%d: seq %u, iv_explicit_ini is not set or tls_record_seq_map is empty.\n", subconn->id, subconn->local_port, seq);
        return -5;
    }

    // while(!subconn->crypto_coder->get_iv_xplct_ini_set() && !tls_record_seq_map->empty() && count < 100){
    //     count++;
    //     usleep(10);
    // }

    if(partial_decrypt)
        return partial_decrypt_tcp_payload(subconn, seq, payload, payload_len, return_buffer);

    if(seq >= cur_ack_rel){
        int decrypt_start = 0, decrypt_end = 0;
        TLS_Encrypted_Record_Reassembler* tls_rcvbuf = subconn->tls_rcvbuf;
        tls_rcvbuf->decrypt_one_payload(seq, payload, payload_len, decrypt_start, decrypt_end, return_buffer);

        if(decrypt_start != 0 || decrypt_end != payload_len){
            tls_rcvbuf->lock();
            if(decrypt_end < payload_len){
                tls_rcvbuf->insert_to_record_fragment(seq+decrypt_end, payload+decrypt_end, payload_len-decrypt_end);
            }
            if(decrypt_start){
                tls_rcvbuf->insert_to_record_fragment(seq, payload, decrypt_start);
            }
            if(!tls_rcvbuf->empty()) {
                tls_rcvbuf->merge_record_fragment();
                tls_rcvbuf->decrypt_record_fragment(return_buffer);
            }
            tls_rcvbuf->unlock();
        }
    }
    return 1;
}

// int process_incoming_tls_payload(unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

// }

// int process_outgoing_tls_payload(unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){

// }




//Assuming the record size doesn't change in the all-but-the-last records
int Optimack::partial_decrypt_tcp_payload(struct subconn_info* subconn, uint seq, unsigned char* payload, int payload_len, std::map<uint, struct record_fragment> &return_buffer){
    // int record_full_size = subconn->record_size;
    // uint record_start_seq = (seq / record_full_size * record_full_size + 1), 
    //      record_end_seq = record_start_seq + record_full_size - 1; 

    // print_func("S%d-%d: Partial: record_start_seq %u, seq+payload_len-1 %u\n", subconn->id, subconn->local_port, record_start_seq, seq+payload_len+1);
    u_char ciphertext[MAX_FULL_GCM_RECORD_LEN+1] = {0};
    u_char plaintext[MAX_FULL_GCM_RECORD_LEN+1] = {0};
    uint record_start_seq = 0, record_end_seq = 0;
    int record_full_size = 0;
    int record_num = 0;

    uint payload_seq_end = seq + payload_len;
    // print_func("S%d-%d: Partial: payload[%u, %u)\n", subconn->id, subconn->local_port, seq, seq + payload_len);

    for(uint payload_index_seq = seq; payload_index_seq + TLSHDR_SIZE < payload_seq_end; payload_index_seq = record_end_seq)
    {
        // print_func("S%d-%d: Partial: find record seq info(%u, %u, %u)\n", subconn->id, subconn->local_port, payload_index_seq, payload_index_seq - seq, payload_len - payload_index_seq + seq);
        TLS_Record_Seq_Info* seq_info = tls_record_seq_map->find_record_seq_info(payload_index_seq, payload + payload_index_seq - seq, payload_len - payload_index_seq + seq, subconn->crypto_coder);
        // while(subconn->tls_record_seq_map->empty());
        // int get_ret = tls_record_seq_map->get_record_seq_info(payload_index_seq, &seq_info);
        if(!seq_info){
            if(tls_debug == -1)
                print_func("S%d-%d: Partial: seq %u 's record info is not found.\n", subconn->id, subconn->local_port, payload_index_seq);
            return -5;
        }
        record_start_seq = seq_info->seq;
        record_num = seq_info->record_num;
        record_end_seq = seq_info->upper_seq;
        record_full_size = seq_info->record_size_with_header;
        if(record_full_size > MAX_FULL_GCM_RECORD_LEN){
            print_func("S%d-%d: Partial: No.%d, record_full_size(%d) > %ld!\n", subconn->id, subconn->local_port, record_num, record_full_size, MAX_FULL_GCM_RECORD_LEN);
            continue;
        }

        Interval record_intvl(record_start_seq, record_end_seq), 
                 payload_intvl(payload_index_seq, payload_seq_end), 
                 intersect = record_intvl.intersect(payload_intvl);
        if(intersect.start > record_start_seq+TLSHDR_SIZE && intersect.start < record_start_seq+TLSHDR_SIZE+8)
            intersect.start = record_start_seq + TLSHDR_SIZE + 8;
        int partial_len = intersect.length();

        if(partial_len <= 0)
            continue;


        if(tls_debug > 0)
            print_func("S%d-%d: Partial: No.%d, Full Record[%u, %u), payload[%u, %u), intersect[%u,%u)\n", subconn->id, subconn->local_port, record_num, record_intvl.start, record_intvl.end, payload_intvl.start, payload_intvl.end, intersect.start, intersect.end);


        uint ciphertext_partial_start_index = intersect.start - record_start_seq, 
             ciphertext_partial_end_index = intersect.end - record_start_seq,
             payload_partial_start_index = intersect.start - seq;
        int plaintext_full_size = record_full_size-TLSHDR_SIZE-8-16;
        if(plaintext_full_size < 0){
            print_func("S%d-%d: Partial: No.%d, plaintext_size < 0! record_size %d\n", subconn->id, subconn->local_port, record_num, record_full_size);
            continue;
        }

        // u_char *ciphertext = new u_char[record_full_size+1],
        //        *plaintext = new u_char[plaintext_full_size+1];
        // if(!ciphertext || !plaintext){
        //     print_func("S%d-%d: Partial: No.%d, new ciphertext(%d) or plaintext(%d) failed.\n", 
        //     subconn->id, subconn->local_port, record_num, record_full_size, plaintext_full_size);
        //     continue;
        // }
        memset(ciphertext, 0, MAX_FULL_GCM_RECORD_LEN+1);
        memset(plaintext, 0, MAX_FULL_GCM_RECORD_LEN+1);
        // memset(ciphertext, 0, record_full_size + 1);
        // memset(plaintext, 0, plaintext_full_size + 1);
        // print_func("partial decrypt: ciphertext_partial_start_index %d, payload_partial_start_index %d, partial_len %d\n", ciphertext_partial_start_index, payload_partial_start_index, partial_len);
        memcpy(ciphertext + ciphertext_partial_start_index, payload + payload_partial_start_index, partial_len);
        int ret = subconn->crypto_coder->decrypt_record(record_num, ciphertext, record_full_size, plaintext);
        if(tls_debug > 2){
            print_func("partial decrypt: ciphertext_seq %u, offset %u\n", record_start_seq, intersect.start - record_start_seq);
            print_hexdump(ciphertext+ciphertext_partial_start_index, partial_len);
        }

        uint plaintext_start_seq = record_start_seq + TLSHDR_SIZE + 8,
             plaintext_end_seq = record_end_seq - 16;
        Interval plaintext_intersect = intersect.intersect(Interval(plaintext_start_seq, plaintext_end_seq));
        int plaintext_partial_len = plaintext_intersect.length();
        uint plaintext_partial_start_index = 0;
        u_char* plaintext_partial_buf = nullptr;
        if(plaintext_partial_len > 0){
            plaintext_partial_start_index = plaintext_intersect.start - plaintext_start_seq;
            plaintext_partial_buf = plaintext + plaintext_partial_start_index;
            if(tls_debug > 0)
                print_func("S%d-%d: Partial: No.%d, seq %u, Full plaintext[%u, %u), payload[%u, %u), intersect[%u,%u)\n", 
                        subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_start_seq, plaintext_end_seq, payload_intvl.start, payload_intvl.end, plaintext_intersect.start, plaintext_intersect.end);
            if(tls_debug > 2){
                print_func("partial decrypt: plaintext_seq %u, offset %u\n", plaintext_start_seq, plaintext_partial_start_index);
                print_hexdump(plaintext_partial_buf, plaintext_partial_len);
            }
        }

        uint tag_start_seq = plaintext_end_seq,
             tag_end_seq = record_end_seq;
        Interval tag_intersect = intersect.intersect(Interval(tag_start_seq, tag_end_seq));
        int tag_partial_len = tag_intersect.length();
        uint tag_partial_start_offset = 0;
        u_char* tag;
        if(tag_partial_len > 0){
            tag_partial_start_offset = tag_intersect.start - tag_start_seq;
            tag = ciphertext + record_full_size - 16 + tag_partial_start_offset;
            if(tls_debug > 0)
                print_func("S%d-%d: Partial: No.%d, seq %u, Full tag[%u, %u), payload[%u, %u), intersect[%u,%u)\n", 
                        subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, tag_start_seq, tag_end_seq, payload_intvl.start, payload_intvl.end, tag_intersect.start, tag_intersect.end);
        }


        if(plaintext_partial_len || tag_partial_len){
            u_char* complete_ciphertext = NULL;
            u_short* participated_ports = NULL;
            int participated_ports_num = 0;
            int complete_ciphertext_len = decrypted_records_map->insert(record_num, plaintext_full_size, subconn->crypto_coder, 
                                                                        plaintext_partial_start_index, plaintext_partial_buf , plaintext_partial_len,
                                                                        tag_partial_start_offset, tag, tag_partial_len, 
                                                                        complete_ciphertext, participated_ports, participated_ports_num);
            if(tls_debug > 0)
                if(complete_ciphertext_len > 0)
                    print_func("S%d-%d: Partial: TLS Record No.%d, seq %u: plaintext[%u, %u)([%u, %u)) inserted, tag[%u, %u)([%u, %u))\n", 
                            subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_intersect.start, plaintext_intersect.end, plaintext_partial_start_index, plaintext_partial_start_index + plaintext_partial_len,
                                                                        tag_intersect.start, tag_intersect.end, tag_partial_start_offset, tag_partial_start_offset + tag_partial_len -1);
                else
                    print_func("S%d-%d: Partial: TLS Record No.%d, seq %u: plaintext[%u, %u)([%u, %u)) not inserted, tag[%u, %u)([%u, %u))\n", 
                            subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_intersect.start, plaintext_intersect.end, plaintext_partial_start_index, plaintext_partial_start_index + plaintext_partial_len,
                                                                        tag_intersect.start, tag_intersect.end, tag_partial_start_offset, tag_partial_start_offset + tag_partial_len -1);

            if(complete_ciphertext_len > 0 && complete_ciphertext){
                if(tls_debug > 0)
                    print_func("S%d-%d: Partial: TLS Record No.%d, seq %u: found complete record, u_char* %p, len %d.\n", subconn->id, subconn->local_port, record_num, payload_partial_start_index, complete_ciphertext, complete_ciphertext_len);
                insert_to_rcvbuf(return_buffer, record_start_seq, complete_ciphertext, complete_ciphertext_len);
                // delete [] complete_ciphertext;
                for(int i = 0; i < participated_ports_num; i++){
                    subconn_info* conn = subconn_infos[participated_ports[i]];
                    try_update_uint_with_lock(&conn->mutex_opa, conn->next_seq_rem_tls, record_start_seq+complete_ciphertext_len);
                }
            }
            if(complete_ciphertext)
                delete [] complete_ciphertext;
            if(participated_ports)
                delete [] participated_ports;
        }
        if(tls_debug > 0){
            print_func("\n");
            print_func("S%d-%d: Partial: seq %u, delete ciphertext %p, plaintext %p\n", subconn->id, subconn->local_port, payload_index_seq, ciphertext, plaintext);
        }
        // print_func("S%d-%d: Partial: done for seq %u\n", subconn->id, subconn->local_port, payload_index_seq);
        // delete [] ciphertext;
        // delete [] plaintext;
    }
    return 0;
}


int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    // int decrypt_start_local = (seq/record_full_size*record_full_size+1) - seq;
    // int decrypt_end_local;
    // if(decrypt_start_local < 0){
    //     // print_func("decrypt_one_payload: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d), add to %d\n", decrypt_start_local, seq_data_start, seq, payload, payload_len, decrypt_start_local+record_full_size);
    //     decrypt_start_local += record_full_size;
    //     if(decrypt_start_local > payload_len){//doesn't contain one full record size
    //         decrypt_start = decrypt_end = 0;
    //         return -1;
    //     }
    //     // exit(-1);
    // }

    // for(decrypt_end_local = decrypt_start_local; decrypt_end_local+record_full_size <= payload_len; decrypt_end_local += record_full_size){
    //     struct mytlshdr* tlshdr = (struct mytlshdr*)(payload+decrypt_end_local);
    //     int tlshdr_len = htons(tlshdr->length);
    //     log_info("TLS Record: version %04x, type %d, len %d(%x), offset %d", tlshdr->version, tlshdr->type, tlshdr_len, tlshdr_len, decrypt_end_local);

    //     if(!( tlshdr->version == version_rvs && tlshdr->type == TLS_TYPE_APPLICATION_DATA ) ){
    //         print_func("decrypt_record_fragment: header not found\n\n");
    //         print_func("After:\n");
    //         print_hexdump(payload, payload_len);
    //         print_func("New header: \n");
    //         print_hexdump(payload+decrypt_end_local, payload_len-decrypt_end_local);
    //         exit(-1);
    //     }
    //     else {
    //         if(tlshdr_len != record_full_size-TLSHDR_SIZE){
    //             print_func("tlshdr length %d != %lu !\n", tlshdr_len, record_full_size-TLSHDR_SIZE);
    //         }
    //         unsigned char plaintext[MAX_FRAG_LEN+1] = {0};//
    //         int plaintext_len = decrypt_record(seq+decrypt_end_local, payload+decrypt_end_local, tlshdr_len + TLSHDR_SIZE, plaintext);
    //         if(plaintext_len > 0){
    //             print_func("decrypt_one_payload: ciphertext_seq %u\nCiphertext:\n", seq+decrypt_end_local);
    //             print_hexdump(payload+decrypt_end_local, record_full_size);
    //             print_func("Plaintext:\n");
    //             print_hexdump(plaintext, plaintext_len);
    //             // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, plaintext, plaintext_len);
    //         }
    //         // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, payload+decrypt_end_local, record_full_size);
    //     }
    // }
    // decrypt_start = decrypt_start_local;
    // decrypt_end = decrypt_end_local;
    return 0;
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
    // print_func("iv_len: %ld\n", iv_len);
    write_key_buffer_len = get_server_write_key(s, write_key_buffer, md, evp_cipher);
    // print_func("write_key_buffer_len: %ld\n", write_key_buffer_len);
    
    // print_func("get_server_write_key: ");
    // for (int i = 0; i < write_key_buffer_len; i++)
    //     print_func("%02x", write_key_buffer[i]);
    // print_func("\n");

    // print_func("get_server_write_iv_salt: ");
    // for(int i = 0; i < 4; i++)
    //     print_func("%02x", iv_salt[i]);
    // print_func("\n");
    return;
}

int SSL_connect_nonblocking(int sockfd, SSL* ssl){

    if(!ssl)
        return -1;
    
    if (fcntl(sockfd, F_SETFL, SOCK_NONBLOCK) == -1) {
        print_func("Could not switch to non-blocking.\n");
        return -1;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    for(int count = 0; count < 3; count++){

        print_func("SSL_connect_nonblocking: fd%d: Attempt %d.\n", sockfd, count);

        int err = SSL_connect(ssl);
        if (err == 1) {
            print_func ("SSL connection using %s\n", SSL_get_cipher (ssl));
            return 1;
        }

        int decodedError = SSL_get_error(ssl, err);

        struct timeval timeout = {1,0};
        if (decodedError == SSL_ERROR_WANT_READ) {
            int result = select(sockfd + 1, &fds, NULL, NULL, &timeout);
            if (result == -1) {
                print_func("Read-select error.\n");
                return -1;
            }
        } else if (decodedError == SSL_ERROR_WANT_WRITE) {
            int result = select(sockfd + 1, NULL, &fds, NULL, &timeout);
            if (result == -1) {
                print_func("Write-select error.\n");
                return -1;
            }
        } else {
            print_func("Error creating SSL connection.  err=%x\n", decodedError);
            return -1;
        }
    }
    return -1;
}


SSL * open_ssl_conn(int sockfd, bool limit_recordsize){
    if(sockfd == 0){
        print_func("open_ssl_conn: sockfd can't be 0!Q\n");
    }
    print_func("open_ssl_conn: for fd %d\n", sockfd);
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

    // const int status = SSL_connect_nonblocking(sockfd, ssl);
    const int status = SSL_connect(ssl);
    if (status != 1)
    {
        int err = SSL_get_error(ssl, status);
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        fprintf(stderr, "open_ssl_conn: fd %d SSL_connect failed with SSL_get_error code %d, %s\n", sockfd, err, msg);
        return nullptr;
    }
    print_func("open_ssl_conn: fd %d Connected with %s encryption\n", sockfd, SSL_get_cipher(ssl));

    // STACK_OF(SSL_CIPHER)* sk = SSL_get1_supported_ciphers(ssl);
    // for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
    //     print_func("%s", SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    // }
    // print_func("\n");
    // free(sk);
    SSL_CTX_free(ctx);

    return ssl;
}



typedef enum
{
    TLS_HANDSHAKE_CLIENT_HELLO               = 1,
    TLS_HANDSHAKE_SERVER_HELLO               = 2
} TlsHandshakeType;


int alter_tls_handshake_hello_extension_max_frag_len(unsigned char *data, int data_len, bool from_server, unsigned char src, unsigned char dst){
    
    if(!data){
        print_func("alter_tls_handshake_hello_extension_max_frag_len: [Error] empty data!\n");
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
            print_func("alter_tls_handshake_hello_extension_max_frag_len: successfully alter value from %u to %u\n", src, dst);
            return 0;
        }
        else{
            print_func("alter_tls_handshake_hello_extension_max_frag_len: [Error]: max_frag_len orig value(%u) not matching dst value(%u)\n", src, dst);
            return -1;
        }
    }
    else{
        print_func("alter_tls_handshake_hello_extension_max_frag_len: [Error]: direction(%u) not matching hello type(%u)\n", from_server, hello_type);
        return -1;
    }

}


// int process_tls_payload(bool in_coming, unsigned int seq, unsigned int ack, unsigned char* payload, int payload_len, TLS_rcvbuf& tls_rcvbuf, std::map<uint, struct record_fragment> &plaintext_buf_local){
unsigned char* find_pos_tls_handshake(unsigned char* tcp_payload, int tcp_payload_len){
    
    if (!tcp_payload){
        print_func("[Error]: find_pos_tls_handshake: empty data!\n");
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
        print_func("parse_tls_handshake: incomplete packet! data len %u, packet len %u\n", data_len, len);
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
        print_func("Received client hello without extensions");
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
//     print_func("parse_max_frag_len_extension: value %d\n", value);
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
//                     print_func("Unknown type: %d letting through\n", tlshdr->type);
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
        //                 print_func("append_max_frag_len: malloc fails!\n");
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
