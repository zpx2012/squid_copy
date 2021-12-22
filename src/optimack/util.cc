
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* struct sockaddr_in */
#include <arpa/inet.h>		/* inet_ntoa */
#include <net/if.h>
#include <unistd.h>		/* close */
#include <stdlib.h>
#include <netdb.h>
#include <time.h>

#include "globals.h"
#include "hping2.h"
#include "logging.h"
#include "socket.h"


/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
        register char *d = dst;
        register const char *s = src;
        register size_t n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0 && --n != 0) {
                do {
                        if ((*d++ = *s++) == 0)
                                break;
                } while (--n != 0);
        }

        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }

        return(s - src - 1);    /* count does not include NUL */
}

/* On error -1 is returned, on success 0 */
int resolve_addr(struct sockaddr * addr, char *hostname)
{
    struct  sockaddr_in *address;
    struct  hostent     *host;

    address = (struct sockaddr_in *)addr;

    memset(address, 0, sizeof(struct sockaddr_in));
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = inet_addr(hostname);

    if ( (int)address->sin_addr.s_addr == -1) {
        host = gethostbyname(hostname);
        if (host) {
            memcpy(&address->sin_addr, host->h_addr,
                host->h_length);
            return 0;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Like resolve_addr but exit on error */
void resolve(struct sockaddr *addr, char *hostname)
{
    if (resolve_addr(addr, hostname) == -1) {
        fprintf(stderr, "Unable to resolve '%s'\n", hostname);
        exit(1);
    }
}

int get_if_name(void)
{
	int fd;
	struct ifconf	ifc;
	struct ifreq	ibuf[16],
			ifr,
			*ifrp,
			*ifend;
	struct sockaddr_in sa;
	struct sockaddr_in output_if_addr;
	int known_output_if = 0;

	/* Try to get the output interface address according to
	 * the OS routing table */
	if (ifname[0] == '\0') {
		if (get_output_if(&remote, &output_if_addr) == 0) {
			known_output_if = 1;
			if (opt_debug)
				printf("DEBUG: Output interface address: %s\n",
					inet_ntoa(sa.sin_addr));
		} else {
			fprintf(stderr, "Warning: Unable to guess the output "
					"interface\n");
		}
	}

	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("[get_if_name] socket(AF_INET, SOCK_DGRAM, 0)");
		return -1;
	}

	memset(ibuf, 0, sizeof(struct ifreq)*16);
	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t) ibuf;

	/* gets interfaces list */
	if ( ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
	     ifc.ifc_len < sizeof(struct ifreq)		) {
		perror("[get_if_name] ioctl(SIOCGIFCONF)");
		close(fd);
		return -1;
	}

	/* ifrp points to buffer and ifend points to buffer's end */
	ifrp = ibuf;
	ifend = (struct ifreq*) ((char*)ibuf + ifc.ifc_len);

	for (; ifrp < ifend; ifrp++) {
		strlcpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));

		if ( ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1) {
			if (opt_debug)
				perror("DEBUG: [get_if_name] ioctl(SIOCGIFFLAGS)");
			continue;
		}

		if (opt_debug)
			printf("DEBUG: if %s: ", ifr.ifr_name);

		/* Down interface? */
		if ( !(ifr.ifr_flags & IFF_UP) )
		{
			if (opt_debug)
				printf("DOWN\n");
			continue;
		}

		if (known_output_if) {
			/* Get the interface address */
			if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1) {
				perror("[get_if_name] ioctl(SIOCGIFADDR)");
				continue;
			}
			/* Copy it */
			memcpy(&sa, &ifr.ifr_addr,
				sizeof(struct sockaddr_in));
			/* Check if it is what we are locking for */
			if (sa.sin_addr.s_addr !=
			    output_if_addr.sin_addr.s_addr) {
				if (opt_debug)
					printf("The address doesn't match\n");
				continue;
			}
		} else if (ifname[0] != '\0' && !strstr(ifr.ifr_name, ifname)) {
			if (opt_debug)
				printf("Don't Match (but seems to be UP)\n");
			continue;
		}

		if (opt_debug)
			printf("OK\n");

		/* interface found, save if name */
		strlcpy(ifname, ifr.ifr_name, 1024);

		/* get if address */
		if ( ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1) {
			perror("DEBUG: [get_if_name] ioctl(SIOCGIFADDR)");
			exit(1);
		}

		/* save if address */
		memcpy(&sa, &ifr.ifr_addr,
			sizeof(struct sockaddr_in));
		strlcpy(ifstraddr, inet_ntoa(sa.sin_addr), 1024);

		/* get if mtu */
		if ( ioctl(fd, SIOCGIFMTU, (char*)&ifr) == -1) {
			perror("Warning: [get_if_name] ioctl(SIOCGIFMTU)");
			fprintf(stderr, "Using a fixed MTU of 1500\n");
			h_if_mtu = 1500;
		}
		else
		{
			h_if_mtu = ifr.ifr_mtu;
		}
		close(fd);
		return 0;
	}
	/* interface not found, use 'lo' */
	strlcpy(ifname, "lo", 1024);
	strlcpy(ifstraddr, "127.0.0.1", 1024);
	h_if_mtu = 1500;

	close(fd);
	return 0;
}

/* Try to obtain the IP address of the output interface according
 * to the OS routing table. Derived from R.Stevens */
int get_output_if(struct sockaddr_in *dest, struct sockaddr_in *ifip)
{
    socklen_t len;
    int sock_rt, on=1;
    struct sockaddr_in iface_out;
 
    memset(&iface_out, 0, sizeof(iface_out));
    sock_rt = socket(AF_INET, SOCK_DGRAM, 0 );

    dest->sin_port = htons(11111);
    if (setsockopt(sock_rt, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))
            == -1) {
        if (opt_debug)
            perror("DEBUG: [get_output_if] setsockopt(SOL_SOCKET, "
                   "SO_BROADCAST");
        close(sock_rt);
        return -1;
    }
  
    if (connect(sock_rt, (struct sockaddr*)dest, sizeof(struct sockaddr_in))
        == -1 ) {
        if (opt_debug)
            perror("DEBUG: [get_output_if] connect");
        close(sock_rt);
        return -1;
    }

    len = sizeof(iface_out);
    if (getsockname(sock_rt, (struct sockaddr *)&iface_out, &len) == -1 ) {
        if (opt_debug)
            perror("DEBUG: [get_output_if] getsockname");
        close(sock_rt);
        return -1;
    }
    close(sock_rt);
    if (iface_out.sin_addr.s_addr == 0)
        return 1;
    memcpy(ifip, &iface_out, sizeof(struct sockaddr_in));
        return 0;
}


void get_local_ip(char *ip)
{
    get_if_name();

    ip[0] = 0;
    strncat(ip, ifstraddr, 16);
}

void get_external_ip(char *ip)
{
    char *head, *tail;
    char buf[64];
    system("wget https://api.ipify.org?format=json -O myip");
    FILE *fp = fopen("myip", "r");
    fgets(buf, 63, fp);
    fclose(fp);

    head = buf;
    while (!(head[0] == 'i' && head[1] == 'p')) head++;
    while (head[0] != ':') head++;
    while (head[0] != '"') head++;
    head++;
    tail = head;
    while (tail[0] != '"') tail++;
    tail[0] = 0;

    ip[0] = 0;
    strncat(ip, head, 16);
}

char* ip2str(u_int32_t ip, char *str)
{
    struct in_addr ia = {ip};
    str[0] = 0;
    strncat(str, inet_ntoa(ia), 16);
    return str;
}

u_int32_t str2ip(const char *str)
{
    struct sockaddr_in addr;
    inet_aton(str, &addr.sin_addr);
    return addr.sin_addr.s_addr;
}

void hex_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    printf("\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count++;
        printf("%02x ", *byte);
        if (count % 16 == 0) printf("\n\t\t");
    }
    printf("\n\n");
}

void human_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    printf("\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count ++; 
        if (isprint(*byte))
            printf("%c", *byte);
        else
            printf(".");
        if (count % 32 == 0) printf("\n\t\t");
    }   
    printf("\n\n");
}

char* hex_dump_str(const unsigned char *packet, size_t size)
{
    char *buf = (char*) malloc(size*3);
    memset(buf, 0, size*3);
    unsigned char *byte = (unsigned char*)packet;
    char tmp[2];
    int count = 0;

    strncat(buf, "\n\n\t\t", 4);
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count++;
        snprintf(tmp, 2, "%02x ", *byte);
        strncat(buf, tmp, 2);
        if (count % 16 == 0) strncat(buf, "\n\t\t", 3);
    }
    strncat(buf, "\n\n", 2);
    return buf;
}

char* tcp_flags_str(u_int8_t flags) 
{
    static char flag_str[64];
    const static char flag_strs[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
    int i;
    int initial = 1;

    flag_str[0] = 0;
    for (i=0; i<6; i++) {
        if ((flags >> i) & 1) {
            if (!initial)
                strncat(flag_str, ",", 1);
            strncat(flag_str, flag_strs[i], 3);
            initial = 0;
        }
    } 
    //log_debug("TCP flags: %s", flag_str);
    return flag_str;
}

void print_fourtuple(struct fourtuple *fourtp)
{
    char sip[16], dip[16];
    log_debug("4-tuple: %s:%d -> %s:%d", ip2str(fourtp->saddr, sip), htons(fourtp->sport), ip2str(fourtp->daddr, dip), htons(fourtp->dport));
}


void show_packet(struct mypacket *packet)
{
    char sip[16], dip[16];
    printf("-------------------------------------\n");
    printf("IP Header:\n");
    printf("+ IHL: %d\n", packet->iphdr->ihl);
    printf("+ Version: %d\n", packet->iphdr->version);
    printf("+ TOS: %d\n", packet->iphdr->tos);
    printf("+ Total length: %d\n", ntohs(packet->iphdr->tot_len));
    printf("+ ID: %d\n", ntohs(packet->iphdr->id));
    printf("+ IP flags: %d\n", (packet->iphdr->frag_off & 0xff) >> 5);
    printf("+ Fragment Offset: %d\n", ((packet->iphdr->frag_off & 0x1f) << 8) + ((packet->iphdr->frag_off & 0xff00) >> 8));
    printf("+ TTL: %d\n", packet->iphdr->ttl);
    printf("+ Protocol: %d\n", packet->iphdr->protocol);
    printf("+ IP checksum: %04x\n", ntohs(packet->iphdr->check));
    printf("+ Source: %s\n", ip2str(packet->iphdr->saddr, sip));
    printf("+ Destination: %s\n", ip2str(packet->iphdr->daddr, dip));
    printf("-------------------------------------\n");
    switch (packet->iphdr->protocol) {
        case 6: // TCP
            printf("\tTCP Header:\n");
            printf("\t+ SPort: %d\n", ntohs(packet->tcphdr->th_sport));
            printf("\t+ DPort: %d\n", ntohs(packet->tcphdr->th_dport));
            printf("\t+ Seq num: %08x\n", ntohl(packet->tcphdr->th_seq));
            printf("\t+ Ack num: %08x\n", ntohl(packet->tcphdr->th_sport));
            printf("\t+ Data offset: %d\n", packet->tcphdr->th_off);
            printf("\t+ TCP flags: %s\n", tcp_flags_str(packet->tcphdr->th_flags));
            printf("\t+ Window: %d\n", ntohs(packet->tcphdr->th_win));
            printf("\t+ TCP checksum: %04x\n", ntohs(packet->tcphdr->th_sum));
            printf("\t+ Urgent pointer: %04x\n", ntohs(packet->tcphdr->th_urp));
            if (packet->tcphdr->th_off != 5) {
                // optional header
                printf("\t+ Optionial:\n");
                hex_dump(((unsigned char*)packet->tcphdr)+packet->tcphdr->th_off*4, packet->tcphdr->th_off*4-20);
            }
            printf("\tTCP Payload:\n");
            hex_dump(packet->payload, packet->payload_len);
            break;
        case 17: // UDP
            printf("\tUDP Header:\n");
            printf("\t+ SPort: %d\n", ntohs(packet->udphdr->uh_sport));
            printf("\t+ DPort: %d\n", ntohs(packet->udphdr->uh_dport));
            printf("\t+ UDP length: %d\n", ntohs(packet->udphdr->uh_ulen));
            printf("\t+ UDP checksum: %04x\n", ntohs(packet->udphdr->uh_sum));
            printf("\tUDP Payload:\n");
            hex_dump(packet->payload, packet->payload_len);
            break;
        default:
            printf("Unkonwn Protocol: %d\n", packet->iphdr->protocol);
            // payload
            hex_dump(packet->data+packet->iphdr->ihl*4, packet->len-packet->iphdr->ihl*4);
    } 
    printf("-------------------------------------\n");
}


unsigned int make_hash(struct fourtuple *f)
{
    unsigned int hash = 0;
    hash = (f->saddr * 59);
    hash ^= f->daddr;
    hash ^= (f->sport << 16 | f->dport);
    return hash;
}

unsigned int make_hash2(unsigned int saddr, unsigned short sport, 
        unsigned int daddr, unsigned short dport) 
{
    unsigned int hash = 0;
    hash = (saddr * 59);
    hash ^= daddr;
    hash ^= (sport << 16 | dport);
    return hash;
}


unsigned int make_hash3(u_int16_t txn_id, const char *qname)
{
    unsigned int hash = 1;
    while (*qname != 0) {
        hash = (hash * 59) + *qname;
        qname++;
    }
    hash ^= txn_id;
    return hash;
}


/* an naive algorithm for checksum calculation */
unsigned int calc_checksum(const unsigned char *payload, unsigned short payload_len)
{
    int i;
    unsigned int checksum = 0, remain = 0;

    /* round down to multiple of 4 */
    unsigned short rd_payload_len = payload_len / 4 * 4;
    for (i = 0; i < rd_payload_len; i += 4) {
        checksum ^= *((unsigned int*)(payload+i));
    }   
    for (i = rd_payload_len; i < payload_len; i++) {
        remain = remain + (payload[i] << (8 * (i - rd_payload_len)));
    }   
    checksum ^= remain;

    return checksum;
}


int choose_appropriate_ttl(int ttl)
{
    if (ttl < 64) {
        return 64 - ttl - 1; // Linux
    } 
    else if (ttl < 128) {
        return 128 - ttl - 1; // Windows
    } 
    else {
        return 254 - ttl - 1; // Others(Solaris/AIX)
    }
}

int is_blocked_ip(const char *ip)
{
    return 1;
}

int startswith(const char *a, const char *b) {
    return (strncmp(a, b, strlen(b)) == 0);
}

timespec diff(timespec end, timespec start)
{
	timespec temp;

	if ((end.tv_nsec - start.tv_nsec) < 0){
		temp.tv_sec = end.tv_sec - start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	}
	else{
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

void traceroute(char *remote_ip, char *output_file)
{
    char cmd[1000];
    sprintf(cmd, "traceroute -A %s > %s", remote_ip, output_file);
    system(cmd);
}
