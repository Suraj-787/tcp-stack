#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stdint.h>
uint16_t compute_checksum(void *buf, int len);
uint16_t tcp_checksum(void *tcp_seg, int tcp_len, uint32_t src_ip, uint32_t dst_ip);
#endif
