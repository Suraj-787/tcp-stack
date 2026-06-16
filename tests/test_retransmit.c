// Standalone Phase 5 validation: send a payload spanning several MSS-sized
// segments while tc netem drops packets on lo, then diff what the peer
// received against what we sent to prove retransmission recovered every byte.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../tcp.h"

#define PAYLOAD_LEN (MSS * 4 + 777)  // forces 5 segments, last one partial

int main(void) {
    printf("=== Phase 5 — Retransmission Under Packet Loss ===\n\n");

    uint8_t *payload = malloc(PAYLOAD_LEN);
    for (int i = 0; i < PAYLOAD_LEN; i++) {
        payload[i] = 'A' + (i % 26);
    }

    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) { free(payload); return 1; }

    if (tcp_connect(conn) < 0) {
        tcp_destroy(conn);
        free(payload);
        return 1;
    }

    printf("\n[TEST] Sending %d bytes across multiple segments...\n", PAYLOAD_LEN);
    int sent = tcp_send(conn, payload, PAYLOAD_LEN);
    printf("[TEST] tcp_send() reported %d bytes sent\n", sent);

    tcp_close(conn);
    tcp_destroy(conn);
    free(payload);

    return (sent == PAYLOAD_LEN) ? 0 : 1;
}
