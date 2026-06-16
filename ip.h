#ifndef IP_H
#define IP_H
#include <stdint.h>
#include "tcp.h"
void build_ip_header(ip_hdr_t *iph, uint32_t src, uint32_t dst,
                     uint16_t payload_len, uint8_t protocol);
#endif
