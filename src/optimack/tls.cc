#include "logging.h"
#include <bits/stdc++.h>

#include "interval.h"
#include "tls.h"
#include "get_server_key_single.h"

#define TLS_DEBUG 1

int print_hexdump(unsigned char* hexdump, int len){
    for(int i = 0; i < len; i++){
        printf("%02x ", hexdump[i]);
        if(i % 16 == 15)
            printf("\n");
    }
    printf("\n");
    // printf("\n\n");
}


int insert_to_rcvbuf(std::map<uint, struct record_fragment> &tls_rcvbuf, uint new_seq_start, unsigned char* new_data, int new_data_len){
    if(!&tls_rcvbuf || !new_data || !new_data_len){
        printf("insert_to_rcvbuf: one of the argument is NULL. tls_rcvbuf %p, new_data %p, new_datalen %d.\n", &tls_rcvbuf, new_data, new_data_len);
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

int TLS_Crypto_Coder::decrypt_record(uint64_t record_num, unsigned char* record_data, int record_len, unsigned char* plaintext){
    if(record_len <= 8 + TLSHDR_SIZE)
        return -1;        

    unsigned char* appdata = record_data + TLSHDR_SIZE;
    int appdata_len = record_len - TLSHDR_SIZE;

    unsigned char* ciphertext = appdata + 8;
    int ciphertext_len = appdata_len - 8 - 16;

    unsigned char iv[13] = {0};
    memcpy(iv, iv_salt, 4);
    unsigned long long iv_num = *((unsigned long long*)appdata);
    if(iv_num){
        memcpy(iv+4, appdata, 8);
        if(TLS_DEBUG){
            printf("decrypt_record: Record No.%lu, iv_num exists ", record_num);
            print_hexdump(appdata, 8);
        }
    }
    else{
        iv_num = htobe64(*((unsigned long long*)iv_xplct_ini));
        iv_num = htobe64(iv_num+record_num-1);
        memcpy(iv+4, &iv_num, 8);
        if(TLS_DEBUG)
            printf("decrypt_record: Record No.%lu, iv_num not exists %x\n", record_num, iv_num);
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

uint map_record_num_to_ciphertext_seq(uint record_num){

}

int TLS_Crypto_Coder::get_aad(uint64_t record_num, int len, unsigned char* aad){
    record_num = htobe64(record_num);
    memcpy(aad, &record_num, 8);
    aad[8] = TLS_TYPE_APPLICATION_DATA;
    *((uint16_t*)(aad+9)) = version_rvs;
    *((uint16_t*)(aad+11)) = ntohs(len);
    aad[13] = 0;
}


TLS_Decrypted_Record_Reassembler::TLS_Decrypted_Record_Reassembler(int rs, int size){
    plntxt_buffer = new Reassembler(0, REASSEM_TCP);
    record_num = rs;
    expected_size = size;
    tags.clear();
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d created\n", this, rs);
}


TLS_Decrypted_Record_Reassembler:: ~TLS_Decrypted_Record_Reassembler(){
    lock();
    cleanup();
    unlock();
}


void TLS_Decrypted_Record_Reassembler::cleanup(){
    // const std::lock_guard<std::mutex> lock(mutex);
    // lock();
    if (TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, cleanup\n", this, record_num);
    
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
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, try lock\n", this, record_num);
    pthread_mutex_lock(&mutex);
}

void TLS_Decrypted_Record_Reassembler::unlock(){
    pthread_mutex_unlock(&mutex);
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, try unlock\n", this, record_num);
}

int TLS_Decrypted_Record_Reassembler::insert_plaintext(TLS_Crypto_Coder* cypto_coder, uint seq, u_char* data, int data_len){
	// const std::lock_guard<std::mutex> lock(mutex);
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, insert plaintext,  plaintext_len %d\n", this, record_num, seq, data_len);
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
        if(TLS_DEBUG)
            printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, insert tag, offset %u, tag_len %d, invalid tag_len! return -1.\n", this, record_num, offset, tag_len);
        return -1;
    }
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, insert tag, offset %u, tag_len %d\n", this, record_num, offset, tag_len);
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
int TLS_Decrypted_Record_Reassembler::check_complete(u_char* &buf, int &buf_len, u_short* &participated_ports, int &participated_ports_len){
	// const std::lock_guard<std::mutex> lock(mutex);
    // printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, check_complete\n", this, record_num);
    lock();
    int verdict = -1;
    if(plntxt_buffer && plntxt_buffer->TotalSize() == expected_size){
        for (auto it = tags.begin(); it != tags.end(); it++){
            if(it->second->TotalSize() == 16){
                if(TLS_DEBUG)
                    printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, plaintext is complete,found tag in coder %p\n", this, record_num, it->first);
                get_complete_plaintext(buf, buf_len);
                u_char* tag = NULL;
                int tag_len = 0;
                tag_len = it->second->InOrderStrs(tag, 16);
                if(tag_len != 16){
                    if(TLS_DEBUG)
                        printf("TLS_Decrypted_Record_Reassembler(%p):No.%d, inserted: tag_len is %d\n", this, record_num, tag_len);
                    continue;
                }
                verdict = verify(buf, buf_len, it->first, tag);
                if(TLS_DEBUG)
                break;
            }
        }
    }
    if(verdict > 0){
        printf("TLS_Decrypted_Record_Reassembler(%p):No.%d, inserted: plaintext is complete, tag verified. run cleanup\n", this, record_num);
        participated_ports_len = tags.size();
        participated_ports = new u_short[participated_ports_len];
        int i = 0;
        for(auto it = tags.begin(); it != tags.end(); it++)
            participated_ports[i++] = it->first->local_port;
    }
    if(verdict >= 0)
        cleanup();

    unlock();
    return verdict;
}

int TLS_Decrypted_Record_Reassembler::get_complete_plaintext(u_char* &buf, int & buf_len){
    buf_len = plntxt_buffer->InOrderStrs(buf, expected_size);
    if (buf_len != expected_size){
        printf("TLS_Decrypted_Record_Reassembler::get_complete_plaintext: Not complete! copied_len %d, expected size %d\n", buf_len, expected_size);
        return -1;
    }

    return buf_len;
}

bool TLS_Decrypted_Record_Reassembler::verify(u_char* plntxt, int plntxt_len, TLS_Crypto_Coder* crypto_coder, u_char* tag){
    //encrypt it to generate ciphertext
    u_char* ciphertext = new u_char[plntxt_len+TLSHDR_SIZE+8+16+1];
    int ciphertext_len = crypto_coder->generate_record(record_num, plntxt, plntxt_len, ciphertext);
    //compare the tag to verify
    if(ciphertext_len){
        ciphertext[ciphertext_len] = 0;
        u_char* regenerated_tag = ciphertext + ciphertext_len - 16;
        int ret = strncmp((char *)(tag), (char *)regenerated_tag, 16);
        if(TLS_DEBUG){
            print_hexdump(tag, 16);
            print_hexdump(regenerated_tag, 16);
            printf("strncmp: %d\n", ret);
        }
        delete [] ciphertext;
        return !ret;
    }
    return false;
}


int TLS_Decrypted_Records_Map::inserted(int record_num, TLS_Decrypted_Record_Reassembler* tls_decrypted_record, u_char* &return_str, u_short* &return_ports, int &return_ports_len){

    if(!tls_decrypted_record)
        return -1;

    //Found the complete tag
    u_char *buf = NULL;
    int buf_len = 0;
    int ret = tls_decrypted_record->check_complete(buf, buf_len, return_ports, return_ports_len);
    if(ret < 0)
        return -1;

    int ciphertext_len = 0;
    if(ret == 1){
        if(TLS_DEBUG){
            printf("inserted: No.%d. Tag verified.\n", record_num);
        }

        u_char* ciphertext = new u_char[buf_len+TLSHDR_SIZE+8+16+1];
        ciphertext_len = main_subconn_cypto_coder->generate_record(record_num, buf, buf_len, ciphertext);
        delete [] buf;
        if(ciphertext_len > 0){
            return_str = ciphertext;
            if(TLS_DEBUG){
                printf("inserted: No.%d. Re-encrypted. assign return_str to %p\n", record_num, ciphertext);
            }

        }
    }
    return ciphertext_len;
}


void TLS_Decrypted_Records_Map::print_result(){
    int incompleted_counter = 0;
    printf("Print TLS_Decrypted_Record_Reassembler:\n");
    for(auto it = decrypted_record_reassembler_map.begin(); it != decrypted_record_reassembler_map.end(); it++){
        // if(it->second == nullptr){
        //     printf("%d:1, ", it->first);
        //     completed_counter++;
        // }
        if(it->second){
            incompleted_counter++;
            printf("%d:%d(%d), ", it->first, it->second->plntxt_buffer->TotalSize(), it->second->expected_size);
        }
    }
    printf("\nIncompleted: %d/%d.\n", incompleted_counter, decrypted_record_reassembler_map.size());
}


void TLS_Decrypted_Records_Map::lock(){
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Records_Map: try lock\n");
    pthread_mutex_lock(&mutex);
}

void TLS_Decrypted_Records_Map::unlock(){
    pthread_mutex_unlock(&mutex);
    if(TLS_DEBUG)
        printf("TLS_Decrypted_Records_Map: try unlock\n");
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
//     if(TLS_DEBUG){
//         printf("insert_plaintext: No.%d, seq %u, len %d\n", record_num, seq, data_len);
//     }
//     return 0;
// }

int TLS_Decrypted_Records_Map::insert(int record_num, int record_size, TLS_Crypto_Coder* crypto_coder, uint seq, u_char* data, int data_len, uint tag_offset, u_char* tag, int tag_len, u_char* &return_str, u_short* &return_ports, int& return_ports_len){
    if (!decrypted_record_reassembler_map.count(record_num)){
        lock();
        if (!decrypted_record_reassembler_map.count(record_num)){
            mutex_map[record_num] = PTHREAD_MUTEX_INITIALIZER;
            decrypted_record_reassembler_map[record_num] = new TLS_Decrypted_Record_Reassembler(record_num, MAX_FRAG_LEN);
        }

        // if(tls_decrypted_record){
        //     if(TLS_DEBUG)
        //         printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, get tls_decrypted_record(%p), record_num %d, plntxt_buffer(%p)\n", tls_decrypted_record, record_num, seq, tls_decrypted_record, tls_decrypted_record->record_num, tls_decrypted_record->plntxt_buffer);

        //     if(!tls_decrypted_record->plntxt_buffer){
        //         // if(TLS_DEBUG)
        //         //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, try lock to delete tls_record\n", tls_decrypted_record, record_num, seq);
        //         // pthread_mutex_lock(mutex_record);
        //         // if(TLS_DEBUG)
        //         //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, gain lock. plntxt_buffer empty, delete it, call cleanup.\n", tls_decrypted_record, record_num, seq);

        //         // delete tls_decrypted_record;
        //         // pthread_mutex_unlock(mutex_record);
        //         // if(TLS_DEBUG)
        //         //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, unlock. Set map entry to nullptr\n", tls_decrypted_record, record_num, seq);

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
        // if(TLS_DEBUG)
        //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, try lock to insert\n", tls_decrypted_record, record_num, seq);
        // pthread_mutex_lock(mutex_record);
        // if(TLS_DEBUG)
        //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, gain lock, inner_recordnum %d, plntxt_buffer(%p)\n", tls_decrypted_record, record_num, seq, tls_decrypted_record->record_num, tls_decrypted_record->plntxt_buffer);
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
                    if(TLS_DEBUG)
                        printf("TLS_Decrypted_Record_Map(%p): No.%d, seq %u, insert_plaintext len %d\n", this, record_num, seq, data_len, tls_decrypted_record->record_num, tls_decrypted_record->plntxt_buffer);
                }
                // pthread_mutex_unlock(mutex_record);
            }

            if(tag && tag_len){
                // pthread_mutex_lock(mutex_record);
                if(tls_decrypted_record->plntxt_buffer && tls_decrypted_record->record_num == record_num){// when tls_decrypted_record is deleted, this pointer will point to any address, plntxt_buffer will not be null, but record_num will not be correct either 
                    tls_decrypted_record->insert_tag(crypto_coder, tag_offset, tag, tag_len);
                    if(TLS_DEBUG){
                        printf("TLS_Decrypted_Record_Map(%p): No.%d, seq %u, insert_tag: offset %u, len %d, ", this, record_num, seq, tag_offset, tag_len);
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
        // if(TLS_DEBUG)
        //     printf("TLS_Decrypted_Record_Reassembler(%p): No.%d, seq %u, unlock\n", tls_decrypted_record, record_num, seq);

        if(ret >= 0){
            // lock();
            
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

int TLS_Record_Number_Seq_Map::insert(uint start_seq, int record_size_with_header){
    lock();
    if(start_seq == next_record_start_seq){
        TLS_Record_Seq_Info* seq_info = new TLS_Record_Seq_Info(record_num_count+1, record_size_with_header, start_seq, start_seq+record_size_with_header);
        tls_seq_map[start_seq] = seq_info;
        next_record_start_seq = start_seq + record_size_with_header;
        if(record_size_with_header && record_size_with_header != MAX_FULL_GCM_RECORD_LEN)
            record_num_count++;
    }
    unlock();
}

int TLS_Record_Number_Seq_Map::set_record_seq_info(uint seq, struct mytlshdr* tlshdr){
    if(tlshdr->version != 0x0303 || tlshdr->type != TLS_TYPE_APPLICATION_DATA){
        if(TLS_DEBUG)
            printf("TLS_Record_Number_Seq_Map: seq %u is not tlshdr\n", seq);
        return -1;
    }

    int cur_record_size = htons(tlshdr->length) + TLSHDR_SIZE;
    set_size(seq, cur_record_size);
    if(cur_record_size != MAX_FULL_GCM_RECORD_LEN)
        printf("TLS_Record_Number_Seq_Map::set_record_seq_info: set record starting at seq %u, length to %d\n", seq, cur_record_size);
    if(cur_record_size != MAX_FULL_GCM_RECORD_LEN)
        insert(seq + cur_record_size, 0);
    return 0;
}

int TLS_Record_Number_Seq_Map::set_size(uint start_seq, int record_size_with_header) {
    if(record_size_with_header == MAX_FULL_GCM_RECORD_LEN){
        if (first_max_frag_seq == 0){        
            lock();
            if (first_max_frag_seq == 0){
                first_max_frag_seq = start_seq;
                if(TLS_DEBUG)
                    printf("TLS_Record_Number_Seq_Map::set_size: set first_max_frag_seq to %u\n", start_seq);
            }
            unlock();
        }
        return -1;
    }
    
    lock();
    if(!tls_seq_map.count(start_seq)){
        if(start_seq > first_max_frag_seq){ //Final piece
            last_piece_start_seq = start_seq;
            tls_seq_map[start_seq] = new TLS_Record_Seq_Info(get_record_num(start_seq), record_size_with_header, start_seq, start_seq+record_size_with_header);
            if(TLS_DEBUG)
                printf("TLS_Record_Number_Seq_Map::set_size: set the final piece length to %d\n", record_size_with_header);
        }
    }
    else{
        TLS_Record_Seq_Info* seq_info = tls_seq_map[start_seq];
        seq_info->record_size_with_header = record_size_with_header;
        seq_info->upper_seq = start_seq + record_size_with_header;
        if(start_seq == next_record_start_seq){
            next_record_start_seq = seq_info->upper_seq;
            record_num_count++;
        }
    }
    unlock();
    return 0;
}

int TLS_Record_Number_Seq_Map::get_record_seq_info(uint seq, TLS_Record_Seq_Info* return_info){
    if(tls_seq_map.empty())
        return -1;

    if(first_max_frag_seq == 0 || (seq < first_max_frag_seq) || (last_piece_start_seq > 0 && seq > last_piece_start_seq)){
        auto it = tls_seq_map.upper_bound(seq);
        TLS_Record_Seq_Info* seq_info = std::prev(it)->second;
        if(seq_info->seq <= seq && seq < seq_info->upper_seq)//Later part comes first?
        {
            return_info->record_num = seq_info->record_num;
            return_info->seq = seq_info->seq;
            return_info->upper_seq = seq_info->upper_seq;
            return_info->record_size_with_header = seq_info->record_size_with_header;
            return 0;
        }
    }
    else{
        int record_num_since_maxfraglen = (seq - first_max_frag_seq) / MAX_FULL_GCM_RECORD_LEN;
        return_info->record_size_with_header = MAX_FULL_GCM_RECORD_LEN;
        return_info->seq = first_max_frag_seq + record_num_since_maxfraglen * return_info->record_size_with_header;
        return_info->upper_seq = return_info->seq + return_info->record_size_with_header;
        return_info->record_num = record_num_count + record_num_since_maxfraglen + 1;
        return 0;
    }
    return -1;
}

int TLS_Record_Number_Seq_Map::get_record_num(uint seq){

    TLS_Record_Seq_Info seq_info;
    int ret = get_record_seq_info(seq, &seq_info);
    if(ret >= 0)
        return seq_info.record_num;
    return -1;
}


void TLS_Record_Number_Seq_Map::lock(){
    if(TLS_DEBUG)
        printf("TLS_Record_Number_Seq_Map: try lock\n");
    pthread_mutex_lock(&mutex);
}

void TLS_Record_Number_Seq_Map::unlock(){
    if(TLS_DEBUG)
        printf("TLS_Record_Number_Seq_Map: try unlock\n");
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
//             printf("Unknown type: %d or tlshdr_len %d <= 8\n", tlshdr->type, tlshdr_len);
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
        printf("S%d-%d: set iv_explicit_ini ", subconn->id, subconn->local_port);
        print_hexdump(payload+TLSHDR_SIZE, 8);
        subconn->crypto_coder->set_iv_explicit_init(payload+TLSHDR_SIZE);

        struct mytlshdr *tlshdr = (struct mytlshdr*)(payload);
        int record_size = htons(tlshdr->length) + TLSHDR_SIZE;

        if(tlshdr->version == subconn->crypto_coder->get_version_reversed()){
            tls_record_seq_map->insert(1, record_size);
            if(record_size != MAX_FULL_GCM_RECORD_LEN)
                tls_record_seq_map->insert(1 + record_size, 0);
        }
    }
    // tls_rcvbuf.decrypt_one_payload(seq, payload, payload_len, decrypt_start, decrypt_end);
    // if(seq >= cur_ack_rel)
        partial_decrypt_tcp_payload(subconn, seq, payload, payload_len, return_buffer);

    // if(decrypt_start != 0 || decrypt_end != payload_len){
    //     tls_rcvbuf.lock();
    //     if(decrypt_end < payload_len){
    //         tls_rcvbuf.insert_to_record_fragment(seq+decrypt_end, payload+decrypt_end, payload_len-decrypt_end);
    //     }
    //     if(decrypt_start){
    //         tls_rcvbuf.insert_to_record_fragment(seq, payload, decrypt_start);
    //     }
    //     if(!tls_rcvbuf.empty()) {
    //         tls_rcvbuf.merge_record_fragment();
    //         tls_rcvbuf.decrypt_record_fragment(plaintext_buf_local);
    //     }
    //     tls_rcvbuf.unlock();
    // }
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

    // printf("S%d-%d: Partial: record_start_seq %u, seq+payload_len-1 %u\n", subconn->id, subconn->local_port, record_start_seq, seq+payload_len+1);
    uint record_start_seq = 0, record_end_seq = 0;
    int record_full_size = 0;
    int record_num = 0;

    uint payload_seq_end = seq + payload_len;
    for(uint payload_index_seq = seq; payload_index_seq + TLSHDR_SIZE < payload_seq_end; payload_index_seq = record_end_seq)
    {
        TLS_Record_Seq_Info seq_info;
        tls_record_seq_map->set_record_seq_info(payload_index_seq, (struct mytlshdr*)(payload + payload_index_seq - seq));
        int get_ret = tls_record_seq_map->get_record_seq_info(payload_index_seq, &seq_info);
        if(get_ret < 0){
            printf("S%d-%d: Partial: record_seq_info for seq %u not found!\n", subconn->id, subconn->local_port, payload_index_seq);
            return -1;
        }
        record_start_seq = seq_info.seq;
        record_num = seq_info.record_num;
        record_end_seq = seq_info.upper_seq;
        record_full_size = seq_info.record_size_with_header;
        if(record_full_size > MAX_FULL_GCM_RECORD_LEN){
            printf("S%d-%d: Partial: No.%d, record_full_size(%d) > %d!\n", subconn->id, subconn->local_port, record_num, record_full_size, MAX_FULL_GCM_RECORD_LEN);
            continue;
        }

        Interval record_intvl(record_start_seq, record_end_seq), 
                 payload_intvl(payload_index_seq, payload_seq_end), 
                 intersect = record_intvl.intersect(payload_intvl);
        int partial_len = intersect.length();

        if(partial_len <= 0)
            continue;


        if(TLS_DEBUG)
            printf("S%d-%d: Partial: No.%d, Full Record[%u, %u), payload[%u, %u), intersect[%u,%u)\n", subconn->id, subconn->local_port, record_num, record_intvl.start, record_intvl.end, payload_intvl.start, payload_intvl.end, intersect.start, intersect.end);


        uint ciphertext_partial_start_index = intersect.start - record_start_seq, 
             ciphertext_partial_end_index = intersect.end - record_start_seq,
             payload_partial_start_index = intersect.start - seq;
        int plaintext_full_size = record_full_size-TLSHDR_SIZE-8-16;
        if(plaintext_full_size < 0){
            printf("S%d-%d: Partial: No.%d, plaintext_size < 0! record_size %d\n", subconn->id, subconn->local_port, record_num, record_full_size);
            continue;
        }

        u_char *ciphertext = new u_char[record_full_size+1],
               *plaintext = new u_char[plaintext_full_size+1];
        if(!ciphertext || !plaintext){
            printf("S%d-%d: Partial: No.%d, new ciphertext(%d) or plaintext(%d) failed.\n", record_full_size, plaintext_full_size);
            continue;
        }
        memset(ciphertext, 0, record_full_size + 1);
        memset(plaintext, 0, plaintext_full_size + 1);
        memcpy(ciphertext + ciphertext_partial_start_index, payload + payload_partial_start_index, partial_len);
        int ret = subconn->crypto_coder->decrypt_record(record_num, ciphertext, record_full_size, plaintext);
        // printf("partial decrypt: ciphertext_seq %u, offset %u\n", record_start_seq, intersect.start - record_start_seq);
        // print_hexdump(ciphertext, MAX_FULL_GCM_RECORD_LEN+1);
    

        uint plaintext_start_seq = record_start_seq + TLSHDR_SIZE + 8,
             plaintext_end_seq = record_end_seq - 16;
        Interval plaintext_intersect = intersect.intersect(Interval(plaintext_start_seq, plaintext_end_seq));
        int plaintext_partial_len = plaintext_intersect.length();
        uint plaintext_partial_start_index = 0;
        u_char* plaintext_partial_buf = nullptr;
        if(plaintext_partial_len > 0){
            plaintext_partial_start_index = plaintext_intersect.start - plaintext_start_seq;
            plaintext_partial_buf = plaintext + plaintext_partial_start_index;
            if(TLS_DEBUG)
                printf("S%d-%d: Partial: No.%d, seq %u, Full plaintext[%u, %u), payload[%u, %u), intersect[%u,%u)\n", 
                        subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_start_seq, plaintext_end_seq, payload_intvl.start, payload_intvl.end, plaintext_intersect.start, plaintext_intersect.end);
        }

        uint tag_start_seq = plaintext_end_seq,
             tag_end_seq = record_end_seq;
        Interval tag_intersect = intersect.intersect(Interval(tag_start_seq, tag_end_seq));
        int tag_partial_len = tag_intersect.length();
        uint tag_partial_start_index = 0;
        u_char* tag;
        if(tag_partial_len > 0){
            tag_partial_start_index = tag_intersect.start - tag_start_seq;
            tag = ciphertext + record_full_size - 16;
            if(TLS_DEBUG)
                printf("S%d-%d: Partial: No.%d, seq %u, Full tag[%u, %u), payload[%u, %u), intersect[%u,%u)\n", 
                        subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, intersect.start, intersect.end, payload_intvl.start, payload_intvl.end, tag_intersect.start, tag_intersect.end);

        }


        if(plaintext_partial_len || tag_partial_len){
            u_char* complete_ciphertext = NULL;
            u_short* participated_ports = NULL;
            int participated_ports_num = 0;
            int complete_ciphertext_len = decrypted_records_map->insert(record_num, plaintext_full_size, subconn->crypto_coder, 
                                                                        plaintext_partial_start_index, plaintext_partial_buf , plaintext_partial_len,
                                                                        tag_partial_start_index, tag, tag_partial_len, 
                                                                        complete_ciphertext, participated_ports, participated_ports_num);
            if(TLS_DEBUG)
                if(complete_ciphertext_len > 0)
                    printf("S%d-%d: Partial: TLS Record No.%d, seq %u: plaintext[%u, %u)([%u, %u)) inserted, tag[%u, %u)([%u, %u))\n", 
                            subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_intersect.start, plaintext_intersect.end, plaintext_partial_start_index, plaintext_partial_start_index + plaintext_partial_len,
                                                                        tag_intersect.start, tag_intersect.end, tag_partial_start_index, tag_partial_start_index + tag_partial_len -1);
                else
                    printf("S%d-%d: Partial: TLS Record No.%d, seq %u: plaintext[%u, %u)([%u, %u)) not inserted, tag[%u, %u)([%u, %u))\n", 
                            subconn->id, subconn->local_port, record_num, plaintext_partial_start_index, plaintext_intersect.start, plaintext_intersect.end, plaintext_partial_start_index, plaintext_partial_start_index + plaintext_partial_len,
                                                                        tag_intersect.start, tag_intersect.end, tag_partial_start_index, tag_partial_start_index + tag_partial_len -1);

            if(complete_ciphertext_len > 0 && complete_ciphertext){
                if(TLS_DEBUG)
                    printf("S%d-%d: Partial: TLS Record No.%d, seq %u: found complete record, u_char* %p, len %d.\n", subconn->id, subconn->local_port, record_num, payload_partial_start_index, complete_ciphertext, complete_ciphertext_len);
                insert_to_rcvbuf(return_buffer, record_start_seq, complete_ciphertext, complete_ciphertext_len);
                delete [] complete_ciphertext;
                for(int i = 0; i < participated_ports_num; i++){
                    subconn_info* conn = subconn_infos[participated_ports[i]];
                    try_update_uint_with_lock(&conn->mutex_opa, conn->next_seq_rem_tls, record_start_seq+complete_ciphertext_len);
                }
            }
        }
        if(TLS_DEBUG)
            printf("\n");

        delete [] ciphertext;
        delete [] plaintext;
    }
}




int decrypt_one_payload(uint seq, unsigned char* payload, int payload_len, int& decrypt_start, int& decrypt_end, std::map<uint, struct record_fragment> &plaintext_rcvbuf){
    // int decrypt_start_local = (seq/record_full_size*record_full_size+1) - seq;
    // int decrypt_end_local;
    // if(decrypt_start_local < 0){
    //     // printf("decrypt_one_payload: seq_header_offset %d < 0, seq_start %u, (%d, %p, %d), add to %d\n", decrypt_start_local, seq_data_start, seq, payload, payload_len, decrypt_start_local+record_full_size);
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
    //         printf("decrypt_record_fragment: header not found\n\n");
    //         printf("After:\n");
    //         print_hexdump(payload, payload_len);
    //         printf("New header: \n");
    //         print_hexdump(payload+decrypt_end_local, payload_len-decrypt_end_local);
    //         exit(-1);
    //     }
    //     else {
    //         if(tlshdr_len != record_full_size-TLSHDR_SIZE){
    //             printf("tlshdr length %d != %lu !\n", tlshdr_len, record_full_size-TLSHDR_SIZE);
    //         }
    //         unsigned char plaintext[MAX_FRAG_LEN+1] = {0};//
    //         int plaintext_len = decrypt_record(seq+decrypt_end_local, payload+decrypt_end_local, tlshdr_len + TLSHDR_SIZE, plaintext);
    //         if(plaintext_len > 0){
    //             printf("decrypt_one_payload: ciphertext_seq %u\nCiphertext:\n", seq+decrypt_end_local);
    //             print_hexdump(payload+decrypt_end_local, record_full_size);
    //             printf("Plaintext:\n");
    //             print_hexdump(plaintext, plaintext_len);
    //             // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, plaintext, plaintext_len);
    //         }
    //         // insert_to_rcvbuf(plaintext_rcvbuf, seq+decrypt_end_local, payload+decrypt_end_local, record_full_size);
    //     }
    // }
    // decrypt_start = decrypt_start_local;
    // decrypt_end = decrypt_end_local;
    // return 0;
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
    if(sockfd == 0){
        printf("open_ssl_conn: sockfd can't be 0!Q\n");
    }
    
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
