#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <netinet/in.h>

// TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// TCP states
typedef enum {
    TCP_CLOSED,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK
} tcp_state_t;

// TCP header — packed so compiler adds no padding bytes
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_off;   // header length (in 32-bit words) shifted left by 4
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed)) tcp_hdr_t;

// IP header
typedef struct {
    uint8_t  ihl_ver;    // version (4 bits) + header length (4 bits)
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed)) ip_hdr_t;

// Pseudo-header used only for checksum calculation
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} __attribute__((packed)) pseudo_hdr_t;

// Reliability: unacknowledged segment tracking (Phase 5)
#define MAX_UNACKED  64
#define RTO_INITIAL  1      // initial retransmission timeout in seconds
#define RTO_MAX      64
#define MAX_RETRIES  5
#define MSS          1460

typedef struct {
    uint8_t  data[MSS];
    int      len;
    uint32_t seq;
    time_t   sent_at;
    int      retries;
    int      in_use;
} segment_t;

// TCP Connection state
typedef struct {
    int      sock;           // raw socket fd
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;            // our current sequence number
    uint32_t ack;            // next seq we expect from peer
    uint32_t send_base;      // oldest unacknowledged seq we've sent
    uint16_t peer_window;    // peer's advertised receive window
    tcp_state_t state;
    segment_t send_buf[MAX_UNACKED];
} tcp_conn_t;

// Function declarations
tcp_conn_t* tcp_create(const char *dst_ip, uint16_t dst_port);
int  tcp_connect(tcp_conn_t *conn);
int  tcp_send(tcp_conn_t *conn, const uint8_t *data, int len);
int  tcp_recv(tcp_conn_t *conn, uint8_t *buf, int buf_len);
void tcp_close(tcp_conn_t *conn);
void tcp_destroy(tcp_conn_t *conn);

#endif
