
#ifndef __SOCKET_H__
#define __SOCKET_H__

void send_SYN(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128);
void send_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128);
void send_request(char* payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128);
void send_FIN_ACK(char *payload, unsigned int ack, unsigned int seq = 1, unsigned short local_port = 8000, unsigned char ttl = 128);
unsigned int wait_SYN_ACK(unsigned int ack = 0, int timeout = 1, unsigned short local_port = 8000, char* pkt_data = NULL);
unsigned int wait_data(unsigned int ack = 0, unsigned int seq = 1, unsigned short local_port = 8000, char* pkt_data = NULL);

void regular_tcp_fastopen_send(char* payload, int len);
void raw_tcp_fastopen_cookie(char* payload, unsigned int seq = 0);
void raw_tcp_fastopen_req(char* payload, unsigned int seq = 0);
void send_fake_SYN(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_spoofed_SYN(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1);
void send_SYN_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_spoofed_SYN_ACK(char *sip, char *dip, unsigned short sport, unsigned short dport, char *payload, unsigned int ack, unsigned int seq = 1);
void send_spoofed_ACK(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1);
void send_spoofed_request(char* fake_ip, char* payload, unsigned int ack, unsigned int seq = 1);
void send_RST(char* payload, unsigned int seq = 1, unsigned char ttl = 128);
void send_wrongcsum_RST(char* payload, unsigned int seq = 1);
void send_RST_ACK(char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_RST_with_MD5(char *payload, unsigned int seq = 1);
void send_FIN(char *payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_FIN_ACK(char *payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);

unsigned int wait_SYN();
unsigned int wait_ACK(unsigned int ack = 0);
unsigned int wait_FIN();
unsigned int wait_FIN_ACK();
unsigned int wait_RST();

void send_a_half_req();
void send_request_seg(char *payload, unsigned int ack, unsigned int seq, unsigned int len);


#endif

