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

// ---------------------------------------------------------------------
// Phase 2: connection setup + raw packet construction/send
// ---------------------------------------------------------------------

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
        close(conn->sock);
        free(conn);
        return NULL;
    }

    // Use loopback for local testing
    conn->src_ip   = inet_addr("127.0.0.1");
    conn->dst_ip   = inet_addr(dst_ip_str);
    conn->src_port = htons(MY_PORT);
    conn->dst_port = htons(dst_port);
    conn->state    = TCP_CLOSED;
    conn->peer_window = 65535;  // assume max until we learn otherwise

    // ISN: randomize to prevent old connection interference
    srand(time(NULL) ^ getpid());
    conn->seq = (uint32_t)rand();

    printf("[TCP] Created connection to %s:%d\n", dst_ip_str, dst_port);
    printf("[TCP] ISN = %u\n", conn->seq);

    return conn;
}

// Test hook: probabilistically drop outgoing data segments instead of
// sending them, so retransmission can be exercised when the host's network
// stack won't honor loss-injecting tools (e.g. tc netem on a virtualized lo).
// Only applies to PSH (data) segments — control packets are never dropped.
// Controlled by env var TCP_SIMULATE_LOSS_PCT (0-100), unset/0 = disabled.
static int should_simulate_drop(uint8_t flags) {
    if (!(flags & TH_PSH)) return 0;
    static int pct = -1;
    if (pct < 0) {
        const char *e = getenv("TCP_SIMULATE_LOSS_PCT");
        pct = e ? atoi(e) : 0;
    }
    if (pct <= 0) return 0;
    return (rand() % 100) < pct;
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

    if (should_simulate_drop(flags)) {
        printf("[SIM] Dropping this data segment (simulated loss)\n");
        free(pkt);
        return 0;  // pretend it was sent so the caller's bookkeeping proceeds
    }

    int sent = sendto(conn->sock, pkt, pkt_len, 0,
                      (struct sockaddr *)&dst, sizeof(dst));
    free(pkt);

    if (sent < 0) {
        perror("sendto failed");
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------
// Phase 5: retransmission + sliding window bookkeeping
// (defined ahead of recv_packet/tcp_connect because recv_packet calls
// process_ack as soon as an ACK arrives, for any state)
// ---------------------------------------------------------------------

// On ACK received — remove acknowledged segments and slide send_base forward.
// TCP ACKs are cumulative: ack_num acknowledges every byte below it, so we
// can advance send_base directly instead of only clearing matching slots.
static void process_ack(tcp_conn_t *conn, uint32_t ack_num) {
    for (int i = 0; i < MAX_UNACKED; i++) {
        if (!conn->send_buf[i].in_use) continue;
        if (conn->send_buf[i].seq + (uint32_t)conn->send_buf[i].len <= ack_num) {
            printf("[TCP] ACK'd segment seq=%u len=%d\n",
                   conn->send_buf[i].seq, conn->send_buf[i].len);
            conn->send_buf[i].in_use = 0;
        }
    }
    // ack_num <= conn->seq always holds for a well-behaved peer
    if (ack_num > conn->send_base && ack_num <= conn->seq) {
        conn->send_base = ack_num;
    }
}

static void retransmit_check(tcp_conn_t *conn) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_UNACKED; i++) {
        if (!conn->send_buf[i].in_use) continue;

        int rto = RTO_INITIAL << conn->send_buf[i].retries;  // exponential backoff
        if (rto > RTO_MAX) rto = RTO_MAX;

        if (now - conn->send_buf[i].sent_at >= rto) {
            if (conn->send_buf[i].retries >= MAX_RETRIES) {
                printf("[TCP] Max retries reached for seq=%u — giving up\n",
                       conn->send_buf[i].seq);
                conn->send_buf[i].in_use = 0;
                continue;
            }
            printf("[TCP] Retransmitting seq=%u (retry %d, RTO=%ds)\n",
                   conn->send_buf[i].seq, conn->send_buf[i].retries + 1, rto);

            // Retransmit using the segment's original seq, then restore conn->seq
            uint32_t saved_seq = conn->seq;
            conn->seq = conn->send_buf[i].seq;
            send_tcp_packet(conn, TH_ACK | TH_PSH,
                            conn->send_buf[i].data, conn->send_buf[i].len);
            conn->seq = saved_seq;

            conn->send_buf[i].sent_at = now;
            conn->send_buf[i].retries++;
        }
    }
}

// ---------------------------------------------------------------------
// Phase 3: receive loop + three-way handshake
// ---------------------------------------------------------------------

// Internal: receive a packet, parse it, and apply ACK/window bookkeeping.
// timeout_sec controls how long to block waiting for the next packet.
static int recv_packet(tcp_conn_t *conn, tcp_hdr_t *out_th, uint8_t *data_buf,
                       int *data_len, int timeout_sec) {
    uint8_t buf[PACKET_BUF];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    struct timeval tv = {timeout_sec, 0};
    setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        int n = recvfrom(conn->sock, buf, PACKET_BUF, 0,
                         (struct sockaddr *)&src_addr, &addr_len);
        if (n < 0) {
            return -1;  // timeout or error — caller decides what that means
        }

        ip_hdr_t  *iph = (ip_hdr_t *)buf;
        int ip_hdr_len = (iph->ihl_ver & 0x0F) * 4;

        // Skip packets not from our peer
        if (iph->src_addr != conn->dst_ip) continue;
        if (iph->protocol != IPPROTO_TCP)  continue;

        tcp_hdr_t *th = (tcp_hdr_t *)(buf + ip_hdr_len);

        // Skip packets not for our port
        if (ntohs(th->dst_port) != MY_PORT) continue;

        printf("[RX] seq=%u ack=%u win=%u ", ntohl(th->seq_num),
               ntohl(th->ack_num), ntohs(th->window));
        log_tcp_flags(th->flags);

        // Track peer's advertised window and process any cumulative ACK
        conn->peer_window = ntohs(th->window);
        if (th->flags & TH_ACK) {
            process_ack(conn, ntohl(th->ack_num));
        }

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
    printf("[STATE] -> %s\n", tcp_state_str(conn->state));

    // Step 2: Wait for SYN+ACK
    printf("[TCP] Waiting for SYN+ACK...\n");
    if (recv_packet(conn, &th, NULL, NULL, 5) < 0) {
        printf("[ERROR] Timed out waiting for SYN+ACK\n");
        return -1;
    }

    if ((th.flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)) {
        printf("[ERROR] Expected SYN+ACK, got flags=0x%02x\n", th.flags);
        return -1;
    }

    // Update our ack to peer's seq+1 (SYN consumes one sequence number)
    conn->ack = ntohl(th.seq_num) + 1;
    // Our seq advances to whatever the peer's ACK says it expects next
    conn->seq = ntohl(th.ack_num);

    printf("[TCP] Got SYN+ACK. peer_seq=%u, our new seq=%u, ack=%u\n",
           ntohl(th.seq_num), conn->seq, conn->ack);

    // Step 3: Send ACK
    if (send_tcp_packet(conn, TH_ACK, NULL, 0) < 0) return -1;
    conn->state = TCP_ESTABLISHED;
    conn->send_base = conn->seq;  // nothing in flight yet
    printf("[STATE] -> %s\n", tcp_state_str(conn->state));
    printf("[TCP] Connection ESTABLISHED\n");

    return 0;
}

// ---------------------------------------------------------------------
// Phase 4/5: data transfer with sliding window + retransmission
// ---------------------------------------------------------------------

int tcp_send(tcp_conn_t *conn, const uint8_t *data, int len) {
    if (conn->state != TCP_ESTABLISHED) {
        printf("[ERROR] Cannot send: not ESTABLISHED\n");
        return -1;
    }

    int sent = 0;

    while (sent < len) {
        // Respect peer's advertised receive window
        uint32_t in_flight = conn->seq - conn->send_base;
        if (in_flight >= conn->peer_window) {
            printf("[TCP] Window full (%u bytes in flight, peer window=%u), waiting...\n",
                   in_flight, conn->peer_window);
            tcp_hdr_t th;
            uint8_t dummy[PACKET_BUF];
            int dummy_len = 0;
            // Briefly poll for an ACK that would slide the window; ignore timeouts
            recv_packet(conn, &th, dummy, &dummy_len, 1);
            retransmit_check(conn);
            continue;
        }

        int chunk = (len - sent) > MSS ? MSS : (len - sent);

        // Find a free slot to track this segment for retransmission
        int slot = -1;
        for (int i = 0; i < MAX_UNACKED; i++) {
            if (!conn->send_buf[i].in_use) { slot = i; break; }
        }
        if (slot == -1) {
            printf("[TCP] Send buffer full, waiting for ACKs...\n");
            tcp_hdr_t th;
            uint8_t dummy[PACKET_BUF];
            int dummy_len = 0;
            recv_packet(conn, &th, dummy, &dummy_len, 1);
            retransmit_check(conn);
            continue;
        }

        conn->send_buf[slot].seq     = conn->seq;
        conn->send_buf[slot].len     = chunk;
        conn->send_buf[slot].sent_at = time(NULL);
        conn->send_buf[slot].retries = 0;
        conn->send_buf[slot].in_use  = 1;
        memcpy(conn->send_buf[slot].data, data + sent, chunk);

        if (send_tcp_packet(conn, TH_ACK | TH_PSH, data + sent, chunk) < 0) {
            return -1;
        }

        conn->seq += chunk;
        sent      += chunk;

        printf("[TCP] Sent %d bytes (total %d/%d)\n", chunk, sent, len);
    }

    // All bytes queued — now drain: keep polling for ACKs and retransmitting
    // until every outstanding segment is acknowledged or gives up after
    // MAX_RETRIES. Without this, data that fits entirely inside the window
    // would be "sent" and never checked again, so a dropped segment would
    // never get retried.
    while (1) {
        int outstanding = 0;
        for (int i = 0; i < MAX_UNACKED; i++) {
            if (conn->send_buf[i].in_use) outstanding++;
        }
        if (outstanding == 0) break;

        tcp_hdr_t th;
        uint8_t dummy[PACKET_BUF];
        int dummy_len = 0;
        recv_packet(conn, &th, dummy, &dummy_len, 1);
        retransmit_check(conn);
    }

    return sent;
}

int tcp_recv(tcp_conn_t *conn, uint8_t *buf, int buf_len) {
    tcp_hdr_t th;
    uint8_t   pkt_data[PACKET_BUF];
    int       data_len = 0;
    int       total    = 0;

    while (total < buf_len - 1) {
        if (recv_packet(conn, &th, pkt_data, &data_len, 5) < 0) break;

        // If we got data, ACK it
        if (data_len > 0) {
            int copy_len = data_len;
            if (total + copy_len > buf_len - 1) copy_len = buf_len - 1 - total;
            memcpy(buf + total, pkt_data, copy_len);
            total += copy_len;

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

// ---------------------------------------------------------------------
// Phase 6: four-way teardown
// ---------------------------------------------------------------------

// Passive close: peer already sent FIN (we're in CLOSE_WAIT and already
// ACKed it in tcp_recv). We just send our own FIN and wait for its ACK.
static void tcp_close_passive(tcp_conn_t *conn) {
    tcp_hdr_t th;

    send_tcp_packet(conn, TH_FIN | TH_ACK, NULL, 0);
    conn->seq++;  // FIN consumes one sequence number
    conn->state = TCP_LAST_ACK;
    printf("[STATE] -> %s\n", tcp_state_str(conn->state));

    if (recv_packet(conn, &th, NULL, NULL, 5) == 0 && (th.flags & TH_ACK)) {
        conn->state = TCP_CLOSED;
        printf("[STATE] -> %s\n", tcp_state_str(conn->state));
        printf("[TCP] Connection closed cleanly\n");
    } else {
        printf("[ERROR] Timed out waiting for ACK of our FIN\n");
        conn->state = TCP_CLOSED;
    }
}

// Active close: we initiate from ESTABLISHED, peer hasn't sent FIN yet.
// Full four-way teardown: FIN -> ACK -> FIN -> ACK, then TIME_WAIT.
static void tcp_close_active(tcp_conn_t *conn) {
    tcp_hdr_t th;

    send_tcp_packet(conn, TH_FIN | TH_ACK, NULL, 0);
    conn->seq++;  // FIN consumes one sequence number
    conn->state = TCP_FIN_WAIT_1;
    printf("[STATE] -> %s\n", tcp_state_str(conn->state));

    // Wait for ACK of our FIN
    if (recv_packet(conn, &th, NULL, NULL, 5) == 0) {
        if (th.flags & TH_ACK) {
            conn->state = TCP_FIN_WAIT_2;
            printf("[STATE] -> %s\n", tcp_state_str(conn->state));
        }
    }

    // Wait for peer's FIN (might have arrived combined with the ACK above)
    if (!(th.flags & TH_FIN)) {
        if (recv_packet(conn, &th, NULL, NULL, 5) < 0) {
            printf("[ERROR] Timed out waiting for peer FIN\n");
            conn->state = TCP_CLOSED;
            return;
        }
    }

    if (th.flags & TH_FIN) {
        conn->ack = ntohl(th.seq_num) + 1;
        send_tcp_packet(conn, TH_ACK, NULL, 0);
        conn->state = TCP_TIME_WAIT;
        printf("[STATE] -> %s\n", tcp_state_str(conn->state));
    }

    // TIME_WAIT: wait 2*MSL before closing (simplified to 4 seconds here)
    printf("[TCP] TIME_WAIT: waiting 4 seconds before close...\n");
    sleep(4);

    conn->state = TCP_CLOSED;
    printf("[STATE] -> %s\n", tcp_state_str(conn->state));
    printf("[TCP] Connection closed cleanly\n");
}

void tcp_close(tcp_conn_t *conn) {
    if (conn->state == TCP_CLOSE_WAIT) {
        tcp_close_passive(conn);
        return;
    }
    if (conn->state != TCP_ESTABLISHED) {
        return;
    }
    tcp_close_active(conn);
}

void tcp_destroy(tcp_conn_t *conn) {
    if (conn) {
        close(conn->sock);
        free(conn);
    }
}
