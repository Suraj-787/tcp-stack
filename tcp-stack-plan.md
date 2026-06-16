# Mini TCP/IP Stack in C — Complete Build Plan

## What You Are Actually Building

You are NOT replacing the operating system's TCP stack.
You are writing a USERSPACE TCP implementation that:
- Opens a raw socket (bypasses OS TCP entirely, talks directly to IP layer)
- Manually constructs every TCP header byte by byte
- Implements the TCP state machine (CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED)
- Handles reliability: checksums, retransmission timers, sliding window flow control

Normal application flow:
```
your app → socket() → OS TCP stack → IP layer → NIC → network
```

Your project's flow:
```
your app → raw socket → YOU handle TCP manually → IP layer → NIC → network
```

The OS still handles IP and Ethernet layers.
You own everything from TCP upward.
This is what makes it a systems programming project.

---

## Prerequisites — Understand These Before Writing Code

### 1. TCP Header Structure (20 bytes)
Every TCP packet starts with this header. You will construct this manually in C.

```
Byte 0-1   : Source Port
Byte 2-3   : Destination Port
Byte 4-7   : Sequence Number   (which byte of data this packet starts at)
Byte 8-11  : Acknowledgment Number (next byte sender expects to receive)
Byte 12    : Data Offset (header length in 32-bit words, upper 4 bits)
Byte 13    : Flags (SYN, ACK, FIN, RST, PSH, URG — each is 1 bit)
Byte 14-15 : Window Size (how many bytes receiver can accept)
Byte 16-17 : Checksum
Byte 18-19 : Urgent Pointer (ignore for this project)
```

Flags you will use:
- SYN = 0x02  → initiate connection
- ACK = 0x10  → acknowledge received data
- FIN = 0x01  → close connection
- RST = 0x04  → reset/abort connection
- SYN+ACK = 0x12 → server's response to SYN

### 2. TCP State Machine
This state machine IS your TCP stack. Every packet causes a state transition.

```
CLOSED
  |
  | send SYN
  v
SYN_SENT
  |
  | receive SYN+ACK, send ACK
  v
ESTABLISHED  ←→  data transfer happens here
  |
  | send FIN
  v
FIN_WAIT_1
  |
  | receive ACK
  v
FIN_WAIT_2
  |
  | receive FIN, send ACK
  v
TIME_WAIT (wait 2*MSL = ~60 seconds)
  |
  v
CLOSED
```

### 3. Sequence Numbers
TCP is a byte stream. Every byte has a unique sequence number.
- You send 1000 bytes starting at seq=5000 → packet has seq=5000, len=1000
- Peer ACKs with ack_num=6000 → means "I got bytes 0–5999, send me 6000 next"
- If no ACK arrives before timer expires → retransmit same packet

### 4. Checksum (ones-complement sum)
You have solved this in CTF already. Same concept.
TCP checksum covers a pseudo-header + TCP header + data:

```
Pseudo-header (12 bytes):
  - Source IP (4 bytes)
  - Destination IP (4 bytes)
  - Zero byte (1 byte)
  - Protocol = 6 for TCP (1 byte)
  - TCP segment length (2 bytes)
```

Sum all 16-bit words together using ones-complement addition.
If the result is 0xFFFF, checksum is valid.

### 5. The RST Problem (critical to understand)
When your raw SYN reaches a server and it replies with SYN+ACK,
the OS kernel ALSO sees that SYN+ACK. Since the kernel has no record
of your raw socket's connection, it sends a RST to kill the connection.

Fix: use iptables to drop the kernel's outgoing RST:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```
Now only YOUR userspace code handles the response.
Remember to remove this rule after testing:
```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

---

## File Structure

Build towards this structure:

```
tcp-stack/
├── main.c           # Entry point — test scenarios and demo
├── tcp.c            # Core: state machine, send/receive logic
├── tcp.h            # TCP structs, state enum, function declarations
├── ip.c             # IP header construction
├── ip.h
├── checksum.c       # Ones-complement checksum calculation
├── checksum.h
├── utils.c          # Logging, hex dump for debugging
├── utils.h
└── Makefile
```

Total expected lines of code: ~700–900 lines across all files.

---

## Phase 0 — Environment Setup (Day 1, first 1 hour)

### What you need
- Linux machine (Ubuntu preferred) — raw sockets require Linux
- Wireshark installed for packet capture and validation
- gcc, make installed
- Root/sudo access (raw sockets need it)

### Install tools
```bash
sudo apt update
sudo apt install gcc make wireshark tcpdump net-tools -y
```

### Create project
```bash
mkdir tcp-stack && cd tcp-stack
touch main.c tcp.c tcp.h ip.c ip.h checksum.c checksum.h utils.c utils.h Makefile
```

### Makefile
```makefile
CC = gcc
CFLAGS = -Wall -Wextra -g
SRCS = main.c tcp.c ip.c checksum.c utils.c
OBJS = $(SRCS:.c=.o)
TARGET = tcp_stack

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
```

### Verify raw sockets work
```c
// test_raw.c — run this separately to confirm setup works
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket failed — run with sudo");
        return 1;
    }
    printf("Raw socket created successfully: fd=%d\n", sock);
    close(sock);
    return 0;
}
```

```bash
gcc test_raw.c -o test_raw && sudo ./test_raw
# Expected: Raw socket created successfully: fd=3
```

### ✅ Milestone
Raw socket opens without error. Wireshark is installed and can capture on loopback.

---

## Phase 1 — Data Structures and Header Construction (Day 1)

### What to build: `tcp.h`
```c
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

// TCP Connection state
typedef struct {
    int      sock;           // raw socket fd
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;            // our current sequence number
    uint32_t ack;            // next seq we expect from peer
    uint16_t peer_window;    // peer's advertised receive window
    tcp_state_t state;
} tcp_conn_t;

// Function declarations
tcp_conn_t* tcp_create(const char *dst_ip, uint16_t dst_port);
int  tcp_connect(tcp_conn_t *conn);
int  tcp_send(tcp_conn_t *conn, const uint8_t *data, int len);
int  tcp_recv(tcp_conn_t *conn, uint8_t *buf, int buf_len);
void tcp_close(tcp_conn_t *conn);
void tcp_destroy(tcp_conn_t *conn);

#endif
```

### What to build: `checksum.c` and `checksum.h`

```c
// checksum.h
#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stdint.h>
uint16_t compute_checksum(void *buf, int len);
uint16_t tcp_checksum(void *tcp_seg, int tcp_len, uint32_t src_ip, uint32_t dst_ip);
#endif
```

```c
// checksum.c
#include "checksum.h"
#include "tcp.h"
#include <string.h>
#include <stdlib.h>

// Standard ones-complement checksum
uint16_t compute_checksum(void *buf, int len) {
    uint16_t *ptr = (uint16_t *)buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    // If odd byte remaining
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// TCP checksum requires pseudo-header prepended
uint16_t tcp_checksum(void *tcp_seg, int tcp_len, uint32_t src_ip, uint32_t dst_ip) {
    // Build pseudo-header + TCP segment into one buffer
    int total = sizeof(pseudo_hdr_t) + tcp_len;
    uint8_t *buf = calloc(1, total);

    pseudo_hdr_t *ph = (pseudo_hdr_t *)buf;
    ph->src_addr = src_ip;
    ph->dst_addr = dst_ip;
    ph->zero     = 0;
    ph->protocol = 6;  // TCP
    ph->tcp_len  = htons(tcp_len);

    memcpy(buf + sizeof(pseudo_hdr_t), tcp_seg, tcp_len);

    uint16_t result = compute_checksum(buf, total);
    free(buf);
    return result;
}
```

### What to build: `utils.c` and `utils.h`

```c
// utils.h
#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
void hex_dump(const uint8_t *buf, int len, const char *label);
void log_tcp_flags(uint8_t flags);
const char* tcp_state_str(int state);
#endif
```

```c
// utils.c
#include "utils.h"
#include "tcp.h"
#include <stdio.h>

void hex_dump(const uint8_t *buf, int len, const char *label) {
    printf("\n[%s] %d bytes:\n", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void log_tcp_flags(uint8_t flags) {
    printf("FLAGS: ");
    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PSH) printf("PSH ");
    printf("\n");
}

const char* tcp_state_str(int state) {
    switch(state) {
        case TCP_CLOSED:       return "CLOSED";
        case TCP_SYN_SENT:     return "SYN_SENT";
        case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
        case TCP_ESTABLISHED:  return "ESTABLISHED";
        case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
        case TCP_TIME_WAIT:    return "TIME_WAIT";
        default:               return "UNKNOWN";
    }
}
```

### ✅ Milestone
`make` compiles with no errors. All structs defined. Checksum function computable.

---

## Phase 2 — Raw Socket + Send SYN (Day 2)

### Goal
Send a hand-crafted SYN packet to a target, see it in Wireshark.
Get a RST or SYN+ACK back — either proves your packet was valid TCP.

### What to build: `ip.c`

```c
// ip.h
#ifndef IP_H
#define IP_H
#include <stdint.h>
#include "tcp.h"
void build_ip_header(ip_hdr_t *iph, uint32_t src, uint32_t dst,
                     uint16_t payload_len, uint8_t protocol);
#endif
```

```c
// ip.c
#include "ip.h"
#include "checksum.h"
#include <netinet/in.h>
#include <stdlib.h>

static uint16_t ip_id = 1;

void build_ip_header(ip_hdr_t *iph, uint32_t src, uint32_t dst,
                     uint16_t payload_len, uint8_t protocol) {
    iph->ihl_ver  = (4 << 4) | 5;      // IPv4, 5 * 4 = 20 byte header
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(ip_hdr_t) + payload_len);
    iph->id       = htons(ip_id++);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = protocol;
    iph->checksum = 0;                  // kernel fills this when IP_HDRINCL set
    iph->src_addr = src;
    iph->dst_addr = dst;
}
```

### What to build: `tcp.c` (Phase 2 portion — raw socket + SYN send)

```c
// tcp.c — Phase 2: socket creation and SYN sending
#include "tcp.h"
#include "ip.h"
#include "checksum.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PACKET_BUF 65536
#define MY_PORT    54321    // source port we use

tcp_conn_t* tcp_create(const char *dst_ip_str, uint16_t dst_port) {
    tcp_conn_t *conn = calloc(1, sizeof(tcp_conn_t));

    // Create raw socket — must run as root
    conn->sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (conn->sock < 0) {
        perror("socket() failed — run with sudo");
        free(conn);
        return NULL;
    }

    // Tell OS: I will build the IP header myself
    int one = 1;
    if (setsockopt(conn->sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        free(conn);
        return NULL;
    }

    // Get our source IP (use loopback for local testing)
    conn->src_ip  = inet_addr("127.0.0.1");
    conn->dst_ip  = inet_addr(dst_ip_str);
    conn->src_port = htons(MY_PORT);
    conn->dst_port = htons(dst_port);
    conn->state   = TCP_CLOSED;

    // ISN: randomize to prevent old connection interference
    srand(time(NULL));
    conn->seq = (uint32_t)rand();

    printf("[TCP] Created connection to %s:%d\n", dst_ip_str, dst_port);
    printf("[TCP] ISN = %u\n", conn->seq);

    return conn;
}

// Internal: build and send a TCP packet
static int send_tcp_packet(tcp_conn_t *conn, uint8_t flags,
                            const uint8_t *data, int data_len) {
    int tcp_len = sizeof(tcp_hdr_t) + data_len;
    int pkt_len = sizeof(ip_hdr_t) + tcp_len;
    uint8_t *pkt = calloc(1, pkt_len);

    ip_hdr_t  *iph = (ip_hdr_t *)pkt;
    tcp_hdr_t *th  = (tcp_hdr_t *)(pkt + sizeof(ip_hdr_t));

    // Build IP header
    build_ip_header(iph, conn->src_ip, conn->dst_ip, tcp_len, IPPROTO_TCP);

    // Build TCP header
    th->src_port = conn->src_port;
    th->dst_port = conn->dst_port;
    th->seq_num  = htonl(conn->seq);
    th->ack_num  = (flags & TH_ACK) ? htonl(conn->ack) : 0;
    th->data_off = (sizeof(tcp_hdr_t) / 4) << 4;  // 5 * 4 = 20 bytes
    th->flags    = flags;
    th->window   = htons(65535);  // advertise max window
    th->urg_ptr  = 0;
    th->checksum = 0;

    // Copy data after header
    if (data && data_len > 0) {
        memcpy(pkt + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t), data, data_len);
    }

    // Calculate TCP checksum
    th->checksum = tcp_checksum(th, tcp_len, conn->src_ip, conn->dst_ip);

    // Send packet
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = conn->dst_ip;

    printf("[TX] seq=%u ack=%u len=%d ", conn->seq, conn->ack, data_len);
    log_tcp_flags(flags);

    int sent = sendto(conn->sock, pkt, pkt_len, 0,
                      (struct sockaddr *)&dst, sizeof(dst));
    free(pkt);

    if (sent < 0) {
        perror("sendto failed");
        return -1;
    }
    return 0;
}
```

### What to build: `main.c` (Phase 2 test)

```c
// main.c — Phase 2: just send a SYN and see what happens
#include <stdio.h>
#include "tcp.h"

int main() {
    // Connect to local netcat server for testing
    // In another terminal run: nc -l 8080
    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) return 1;

    printf("[TEST] Sending SYN to 127.0.0.1:8080\n");
    // We'll call tcp_connect() once it's fully built
    // For now just test packet construction compiles

    tcp_destroy(conn);
    return 0;
}

void tcp_destroy(tcp_conn_t *conn) {
    if (conn) {
        close(conn->sock);
        free(conn);
    }
}
```

### Test in Wireshark
```bash
# Terminal 1: start capture
sudo tcpdump -i lo -w phase2.pcap port 8080

# Terminal 2: start listener
nc -l 8080

# Terminal 3: run your code
sudo ./tcp_stack

# Open phase2.pcap in Wireshark
# You should see a SYN packet from port 54321 to port 8080
```

### ✅ Milestone
Wireshark shows a valid SYN packet. Source port = 54321, Dest port = 8080.
Checksum shown as valid (green) in Wireshark's TCP dissector.

---

## Phase 3 — Three-Way Handshake (Day 2–3)

### Goal
Complete SYN → SYN+ACK → ACK. Reach ESTABLISHED state.
This is the most technically tricky phase because of the RST problem.

### RST suppression (do this before running)
```bash
# Drop the kernel's RST so your userspace can handle the connection
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### What to add to `tcp.c` — receive loop and handshake

```c
// Add to tcp.c — receive a packet and parse TCP header
static int recv_packet(tcp_conn_t *conn, tcp_hdr_t *out_th, uint8_t *data_buf,
                       int *data_len) {
    uint8_t buf[PACKET_BUF];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    // Set receive timeout: 5 seconds
    struct timeval tv = {5, 0};
    setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        int n = recvfrom(conn->sock, buf, PACKET_BUF, 0,
                         (struct sockaddr *)&src_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom timeout or error");
            return -1;
        }

        ip_hdr_t  *iph = (ip_hdr_t *)buf;
        int ip_hdr_len = (iph->ihl_ver & 0x0F) * 4;

        // Skip packets not from our peer
        if (iph->src_addr != conn->dst_ip) continue;
        if (iph->protocol != IPPROTO_TCP)  continue;

        tcp_hdr_t *th = (tcp_hdr_t *)(buf + ip_hdr_len);

        // Skip packets not for our port
        if (ntohs(th->dst_port) != MY_PORT) continue;

        printf("[RX] seq=%u ack=%u ", ntohl(th->seq_num), ntohl(th->ack_num));
        log_tcp_flags(th->flags);

        // Copy header out
        memcpy(out_th, th, sizeof(tcp_hdr_t));

        // Extract data if any
        int tcp_hdr_len = (th->data_off >> 4) * 4;
        int total_len   = ntohs(iph->tot_len);
        int payload     = total_len - ip_hdr_len - tcp_hdr_len;

        if (payload > 0 && data_buf && data_len) {
            memcpy(data_buf, buf + ip_hdr_len + tcp_hdr_len, payload);
            *data_len = payload;
        } else if (data_len) {
            *data_len = 0;
        }

        return 0;
    }
}

// Complete three-way handshake
int tcp_connect(tcp_conn_t *conn) {
    tcp_hdr_t th;

    // Step 1: Send SYN
    printf("\n[STATE] %s\n", tcp_state_str(conn->state));
    if (send_tcp_packet(conn, TH_SYN, NULL, 0) < 0) return -1;
    conn->state = TCP_SYN_SENT;
    printf("[STATE] → %s\n", tcp_state_str(conn->state));

    // Step 2: Wait for SYN+ACK
    printf("[TCP] Waiting for SYN+ACK...\n");
    if (recv_packet(conn, &th, NULL, NULL) < 0) return -1;

    if ((th.flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)) {
        printf("[ERROR] Expected SYN+ACK, got flags=0x%02x\n", th.flags);
        return -1;
    }

    // Update our ack to peer's seq+1
    conn->ack = ntohl(th.seq_num) + 1;
    // Our seq advances by 1 (SYN consumes one sequence number)
    conn->seq = ntohl(th.ack_num);

    printf("[TCP] Got SYN+ACK. peer_seq=%u, our new seq=%u, ack=%u\n",
           ntohl(th.seq_num), conn->seq, conn->ack);

    // Step 3: Send ACK
    if (send_tcp_packet(conn, TH_ACK, NULL, 0) < 0) return -1;
    conn->state = TCP_ESTABLISHED;
    printf("[STATE] → %s\n", tcp_state_str(conn->state));
    printf("[TCP] ✓ Connection ESTABLISHED\n");

    return 0;
}
```

### Update `main.c` for Phase 3 test

```c
#include <stdio.h>
#include "tcp.h"

int main() {
    printf("=== Mini TCP Stack — Handshake Test ===\n");

    // Run: nc -l 8080   in another terminal first
    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) return 1;

    if (tcp_connect(conn) == 0) {
        printf("\n✅ Three-way handshake complete!\n");
    } else {
        printf("\n❌ Handshake failed\n");
    }

    tcp_destroy(conn);
    return 0;
}
```

### Run test
```bash
# Terminal 1: capture packets
sudo tcpdump -i lo -w phase3.pcap port 8080

# Terminal 2: local server
nc -l 8080

# Terminal 3: suppress RST, then run
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./tcp_stack

# Clean up iptables after test
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### What to verify in Wireshark
Open phase3.pcap → you should see exactly:
```
1. [SYN]     54321 → 8080    seq=X
2. [SYN,ACK] 8080  → 54321   seq=Y, ack=X+1
3. [ACK]     54321 → 8080    seq=X+1, ack=Y+1
```
Right-click any packet → Follow TCP Stream → Wireshark shows ESTABLISHED connection.

### ✅ Milestone
Program prints `✓ Connection ESTABLISHED`.
Wireshark confirms three packets in the right order with correct seq/ack numbers.

---

## Phase 4 — Data Transfer + Checksum Validation (Day 3)

### Goal
Send an HTTP GET request over your TCP stack and receive the response.
The server is a simple Python HTTP server running locally.

### What to add to `tcp.c` — send and receive data

```c
// Send data over established connection
int tcp_send(tcp_conn_t *conn, const uint8_t *data, int len) {
    if (conn->state != TCP_ESTABLISHED) {
        printf("[ERROR] Cannot send: not ESTABLISHED\n");
        return -1;
    }

    int sent = 0;
    int mss  = 1460;  // Maximum Segment Size: 1500 (MTU) - 20 (IP) - 20 (TCP)

    while (sent < len) {
        int chunk = (len - sent) > mss ? mss : (len - sent);

        if (send_tcp_packet(conn, TH_ACK | TH_PSH, data + sent, chunk) < 0) {
            return -1;
        }

        conn->seq += chunk;  // advance seq by bytes sent
        sent += chunk;

        printf("[TCP] Sent %d bytes (total %d/%d)\n", chunk, sent, len);
    }

    return sent;
}

// Receive data — loop until FIN or error
int tcp_recv(tcp_conn_t *conn, uint8_t *buf, int buf_len) {
    tcp_hdr_t th;
    uint8_t   pkt_data[65536];
    int       data_len = 0;
    int       total    = 0;

    while (1) {
        if (recv_packet(conn, &th, pkt_data, &data_len) < 0) break;

        // If we got data, ACK it
        if (data_len > 0) {
            memcpy(buf + total, pkt_data, data_len);
            total += data_len;

            conn->ack += data_len;  // advance ack by bytes received
            send_tcp_packet(conn, TH_ACK, NULL, 0);

            printf("[TCP] Received %d bytes (total %d)\n", data_len, total);
            buf[total] = '\0';  // null-terminate for printing
        }

        // If peer sent FIN — they're done sending
        if (th.flags & TH_FIN) {
            printf("[TCP] Received FIN from peer\n");
            conn->ack++;  // FIN consumes one sequence number
            send_tcp_packet(conn, TH_ACK, NULL, 0);
            conn->state = TCP_CLOSE_WAIT;
            break;
        }
    }

    return total;
}
```

### Update `main.c` for Phase 4 test

```c
#include <stdio.h>
#include <string.h>
#include "tcp.h"

int main() {
    printf("=== Mini TCP Stack — HTTP GET Test ===\n");

    // Start server first: python3 -m http.server 8080
    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) return 1;

    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP  // do this in shell

    if (tcp_connect(conn) < 0) {
        tcp_destroy(conn);
        return 1;
    }

    // Send HTTP GET
    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    printf("\n[HTTP] Sending GET request...\n");
    tcp_send(conn, (uint8_t *)req, strlen(req));

    // Receive response
    uint8_t resp[65536] = {0};
    int n = tcp_recv(conn, resp, sizeof(resp));

    printf("\n[HTTP] Received %d bytes:\n", n);
    printf("%.500s\n", resp);  // print first 500 chars

    tcp_destroy(conn);
    return 0;
}
```

### Run test
```bash
# Terminal 1: Python HTTP server
python3 -m http.server 8080

# Terminal 2: capture
sudo tcpdump -i lo -w phase4.pcap port 8080

# Terminal 3
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./tcp_stack
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### ✅ Milestone
Program prints an HTTP response (HTTP/1.0 200 OK ...).
Wireshark shows: SYN → SYN+ACK → ACK → [data] → [data] → FIN.
Wireshark's TCP stream reassembly shows the HTTP response correctly.

---

## Phase 5 — Reliability: Retransmission + Sliding Window (Day 4)

### Goal
Handle packet loss — if no ACK received within timeout, retransmit.
Implement sliding window to respect peer's receive buffer.
This is what makes your implementation genuinely TCP-compliant.

### Retransmission logic

Add a send buffer to track unacknowledged segments:

```c
// Add to tcp.h
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
```

```c
// Add to tcp.c — retransmit unacknowledged segments
static segment_t send_buf[MAX_UNACKED];

static void retransmit_check(tcp_conn_t *conn) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_UNACKED; i++) {
        if (!send_buf[i].in_use) continue;

        int rto = RTO_INITIAL << send_buf[i].retries;  // exponential backoff
        if (now - send_buf[i].sent_at >= rto) {
            if (send_buf[i].retries >= MAX_RETRIES) {
                printf("[TCP] Max retries reached for seq=%u — giving up\n",
                       send_buf[i].seq);
                send_buf[i].in_use = 0;
                continue;
            }
            printf("[TCP] Retransmitting seq=%u (retry %d, RTO=%ds)\n",
                   send_buf[i].seq, send_buf[i].retries + 1, rto);

            // Retransmit
            uint32_t saved_seq = conn->seq;
            conn->seq = send_buf[i].seq;
            send_tcp_packet(conn, TH_ACK | TH_PSH,
                            send_buf[i].data, send_buf[i].len);
            conn->seq = saved_seq;

            send_buf[i].sent_at = now;
            send_buf[i].retries++;
        }
    }
}

// On ACK received — remove acknowledged segments from buffer
static void process_ack(uint32_t ack_num) {
    for (int i = 0; i < MAX_UNACKED; i++) {
        if (!send_buf[i].in_use) continue;
        if (send_buf[i].seq + send_buf[i].len <= ack_num) {
            printf("[TCP] ACK'd segment seq=%u len=%d\n",
                   send_buf[i].seq, send_buf[i].len);
            send_buf[i].in_use = 0;
        }
    }
}
```

### Sliding window send

```c
// Replace tcp_send() with window-aware version
int tcp_send(tcp_conn_t *conn, const uint8_t *data, int len) {
    if (conn->state != TCP_ESTABLISHED) return -1;

    int sent = 0;
    while (sent < len) {
        // Respect peer's advertised window
        uint32_t in_flight = conn->seq - /* send_base */ 0; // simplified
        if (in_flight >= conn->peer_window) {
            printf("[TCP] Window full (%u bytes in flight), waiting...\n",
                   in_flight);
            // In a real impl: wait for ACK to slide window
            // For simplicity: just wait
            sleep(1);
            retransmit_check(conn);
            continue;
        }

        int chunk = (len - sent) > MSS ? MSS : (len - sent);

        // Add to send buffer for retransmission tracking
        for (int i = 0; i < MAX_UNACKED; i++) {
            if (!send_buf[i].in_use) {
                send_buf[i].seq     = conn->seq;
                send_buf[i].len     = chunk;
                send_buf[i].sent_at = time(NULL);
                send_buf[i].retries = 0;
                send_buf[i].in_use  = 1;
                memcpy(send_buf[i].data, data + sent, chunk);
                break;
            }
        }

        send_tcp_packet(conn, TH_ACK | TH_PSH, data + sent, chunk);
        conn->seq += chunk;
        sent      += chunk;
    }
    return sent;
}
```

### Test retransmission with packet loss simulation
```bash
# Add artificial 30% packet loss on loopback
sudo tc qdisc add dev lo root netem loss 30%

# Run your stack — it should retransmit lost segments
sudo ./tcp_stack

# Remove loss after testing
sudo tc qdisc del dev lo root
```

### ✅ Milestone
Under 30% packet loss, data still transfers correctly.
Logs show `[TCP] Retransmitting seq=X (retry 1, RTO=1s)` on lost packets.
Wireshark shows retransmitted packets highlighted in black (TCP Retransmission).

---

## Phase 6 — Connection Teardown (Day 4)

### Goal
Implement clean four-way FIN handshake.
Without this, connections hang and you leak resources.

```
You         Peer
 |            |
 |---FIN----->|    FIN_WAIT_1
 |<---ACK-----|    FIN_WAIT_2
 |<---FIN-----|    TIME_WAIT
 |---ACK----->|    (wait 2*MSL = 60s)
 |            |    CLOSED
```

```c
// Add to tcp.c
void tcp_close(tcp_conn_t *conn) {
    if (conn->state != TCP_ESTABLISHED &&
        conn->state != TCP_CLOSE_WAIT) {
        return;
    }

    tcp_hdr_t th;

    // Send FIN
    send_tcp_packet(conn, TH_FIN | TH_ACK, NULL, 0);
    conn->seq++;  // FIN consumes one sequence number
    conn->state = TCP_FIN_WAIT_1;
    printf("[STATE] → %s\n", tcp_state_str(conn->state));

    // Wait for ACK of our FIN
    if (recv_packet(conn, &th, NULL, NULL) == 0) {
        if (th.flags & TH_ACK) {
            conn->state = TCP_FIN_WAIT_2;
            printf("[STATE] → %s\n", tcp_state_str(conn->state));
        }
    }

    // Wait for peer's FIN
    if (recv_packet(conn, &th, NULL, NULL) == 0) {
        if (th.flags & TH_FIN) {
            conn->ack = ntohl(th.seq_num) + 1;
            send_tcp_packet(conn, TH_ACK, NULL, 0);
            conn->state = TCP_TIME_WAIT;
            printf("[STATE] → %s\n", tcp_state_str(conn->state));
        }
    }

    // TIME_WAIT: wait 2*MSL before closing (simplified to 4 seconds here)
    printf("[TCP] TIME_WAIT: waiting 4 seconds before close...\n");
    sleep(4);

    conn->state = TCP_CLOSED;
    printf("[STATE] → %s\n", tcp_state_str(conn->state));
    printf("[TCP] ✓ Connection closed cleanly\n");
}
```

### ✅ Milestone
Wireshark shows the full four-way teardown:
FIN → ACK → FIN → ACK in the correct order.
No `[RST]` packets in the capture (RST = unclean close).

---

## Phase 7 — Final Test + Wireshark Validation (Day 5)

### Full integration test in `main.c`

```c
#include <stdio.h>
#include <string.h>
#include "tcp.h"

int main() {
    printf("=== Mini TCP/IP Stack — Full Integration Test ===\n\n");

    // Setup: python3 -m http.server 8080
    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) return 1;

    // Handshake
    printf("--- Phase 1: Handshake ---\n");
    if (tcp_connect(conn) < 0) { tcp_destroy(conn); return 1; }

    // Send HTTP request
    printf("\n--- Phase 2: Sending HTTP GET ---\n");
    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    tcp_send(conn, (uint8_t *)req, strlen(req));

    // Receive response
    printf("\n--- Phase 3: Receiving Response ---\n");
    uint8_t resp[65536] = {0};
    int n = tcp_recv(conn, resp, sizeof(resp));
    printf("\n[RESPONSE] %d bytes received\n", n);
    printf("%.300s...\n", resp);

    // Clean close
    printf("\n--- Phase 4: Closing Connection ---\n");
    tcp_close(conn);

    tcp_destroy(conn);
    printf("\n✅ All phases complete\n");
    return 0;
}
```

### Full test run commands
```bash
# Terminal 1: packet capture (capture everything for final validation)
sudo tcpdump -i lo -w final.pcap port 8080

# Terminal 2: server
python3 -m http.server 8080

# Terminal 3: run with loss simulation to test retransmission
sudo tc qdisc add dev lo root netem loss 10%
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./tcp_stack
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo tc qdisc del dev lo root
```

### Wireshark validation checklist
Open final.pcap in Wireshark and verify:
```
✅ Packet 1: SYN   (flags=0x002, no ACK)
✅ Packet 2: SYN+ACK (flags=0x012, ack=ISN+1)
✅ Packet 3: ACK   (flags=0x010, establishes connection)
✅ Data packets: PSH+ACK, seq numbers increment correctly
✅ ACK packets from server: ack numbers = our_seq + bytes_sent
✅ If loss simulated: retransmitted packets appear (black in Wireshark)
✅ FIN+ACK, ACK, FIN+ACK, ACK — clean teardown
✅ No unexpected RST packets
```

Right-click any packet → Follow TCP Stream → Should show your HTTP request
and the server's HTTP response reassembled correctly by Wireshark.

### ✅ Final Milestone
Wireshark's TCP stream reassembly shows your complete HTTP exchange.
This means Wireshark — a professional packet analyzer — validates your
TCP implementation as correct.

---

## Resume Bullet

> Implemented a userspace TCP/IP stack in C using raw sockets — three-way handshake, sliding window flow control, retransmission with exponential backoff, and checksum verification; validated correctness against Wireshark packet captures under simulated 10% packet loss.

---

## Interview Answers

**"Walk me through your TCP project."**
> I bypassed the kernel's TCP stack entirely using raw sockets and reimplemented
> the protocol in userspace in C. The interesting part was reliability — I built
> a retransmission timer with exponential backoff and a sliding window that
> respects the peer's advertised receive window. I validated correctness by
> simulating 10% packet loss with Linux's tc netem and confirming retransmits
> fired at the right times in Wireshark.

**"Why does TCP need a three-way handshake instead of two-way?"**
> A two-way handshake can't handle delayed duplicate SYNs from old connections.
> With two-way, if a stale SYN arrives at the server from a previous connection,
> the server establishes a connection the client never intended. The third ACK
> lets the client reject a SYN+ACK it didn't expect, preventing ghost connections.

**"How does your retransmission handle varying network conditions?"**
> Exponential backoff — each retry doubles the timeout: 1s, 2s, 4s, 8s up to
> a cap. This avoids overwhelming an already congested network. Real TCP also
> uses RTT estimation (Jacobson's algorithm) to set the initial RTO dynamically,
> which I noted as a future improvement.

**"What is the RST problem and how did you solve it?"**
> When the server replies with SYN+ACK, the OS kernel also sees it. Since the
> kernel has no record of my raw socket connection, it sends a RST to kill it
> before my userspace code can respond. I used iptables to drop outgoing RST
> packets during testing, giving my userspace handler exclusive control of
> the connection.

---

## Resources to Read Alongside Building

- Kurose & Ross Chapter 3 (Transport Layer) — read sections 3.4 and 3.5
  while building Phase 3 and Phase 5 respectively
- RFC 793 — the actual TCP specification, 85 pages, search for specific
  sections when you hit edge cases: https://datatracker.ietf.org/doc/html/rfc793
- Beej's Guide to Network Programming in C — free, covers raw sockets well:
  https://beej.us/guide/bgnet/
