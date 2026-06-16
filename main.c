#include <stdio.h>
#include <string.h>
#include "tcp.h"

int main(void) {
    printf("=== Mini TCP/IP Stack — Full Integration Test ===\n\n");

    // Target: python3 -m http.server 8080 (or `nc -l 8080` for earlier phases)
    tcp_conn_t *conn = tcp_create("127.0.0.1", 8080);
    if (!conn) return 1;

    printf("--- Phase 1: Handshake ---\n");
    if (tcp_connect(conn) < 0) {
        tcp_destroy(conn);
        return 1;
    }

    printf("\n--- Phase 2: Sending HTTP GET ---\n");
    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    tcp_send(conn, (uint8_t *)req, strlen(req));

    printf("\n--- Phase 3: Receiving Response ---\n");
    uint8_t resp[65536] = {0};
    int n = tcp_recv(conn, resp, sizeof(resp));
    printf("\n[RESPONSE] %d bytes received\n", n);
    printf("%.300s...\n", resp);

    printf("\n--- Phase 4: Closing Connection ---\n");
    tcp_close(conn);

    tcp_destroy(conn);
    printf("\nAll phases complete\n");
    return 0;
}
