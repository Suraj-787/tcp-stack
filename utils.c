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
        case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
        case TCP_LAST_ACK:     return "LAST_ACK";
        default:               return "UNKNOWN";
    }
}
