#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
void hex_dump(const uint8_t *buf, int len, const char *label);
void log_tcp_flags(uint8_t flags);
const char* tcp_state_str(int state);
#endif
