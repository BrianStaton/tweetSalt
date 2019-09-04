#ifndef _NACL_SUPPORT_H_
#define _NACL_SUPPORT_H_
#include <stdio.h>
#include <stdint.h>

void randombytes(uint8_t *data, uint64_t n);
void randombytes_buf(uint8_t *data, size_t n);

#endif
