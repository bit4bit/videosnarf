#ifndef VIDEOSNARF_H
#define VIDEOSNARF_H

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <config.h>

#define SNAPLEN         8192 
#define PROMISC         1
#define TIMEOUT         500
#define ETHSIZE         14
#define UDPSIZE         8
#define ARTPSIZE        12
#define VRTPSIZE        12
#define MAXPKTCOUNT     50
//#define ETHER_ADDR_LEN  0x06	
#define RTPSIZE			12
#define DISPLAY 		16
#define LINUX_COOKED	16

#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
//#define ETHERTYPE_IP          0x0008          /* IP */
#define ETHERTYPE_1Q			0x8100
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */
#define ETHERTYPE_AUTH          0x888e          /* 802.1x Authentication */

/* Ethernet Header */
struct sniff_ethernet
{
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* TCP Header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp
{
        u_short source;                 /* Source port */
        u_short dest;                   /* Destination Port */
        u_short len;                    /* Total Len */
        u_short check;                  /* Checksum */
};


struct sniff_rtp
{
        u_char version;               /* Protocol Version */
        u_char payloadType;           /* Payload Type */
        u_short sequence_no;          /* Sequence Number */
        u_int timestamp;             /* TimeStamp */
        u_int ssrc;                  /* Symchronization Source */
};

struct logical_link_control {
        u_char  dsapigbit[1];
        u_char  ssapcrbit[1];
        u_char  controlfield[1];
        u_char  organizationc[3];
        u_char  pid[2];
};

struct vlan_header {
        u_char  other[2];
        u_short length;
};

void mediasnarfStart();									/* Starts snarfing media packets */
void mediasnarfStop();									/* Stops snarfing media packets */
int dump_payload(unsigned char *payload, int len,FILE *fp);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);              /* Our callBack Function.*/
void packet_handler_rawip(u_char *dummy, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void packet_handler_linuxcooked(u_char *dummy, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void decode_ip(const u_char *pkt_data,u_char *args);                                      /* IP Packet Dissector. */
void print_payload(const u_char *payload, int len);                                     /* Prints the TCP payload. */
void print_hex_ascii_line(const u_char *payload, int len, int offset);                  /* Prints in HEX. */

#endif
