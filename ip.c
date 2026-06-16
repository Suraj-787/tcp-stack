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
