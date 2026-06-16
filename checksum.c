#include "checksum.h"
#include "tcp.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

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
