#include "naclSupport.h"
#include <stdlib.h>

void randombytes(uint8_t *data, uint64_t n)
{
    while (n)
    {
        *data++ = (uint8_t)(rand() % 0xFF);
        n--;
    }
}

void randombytes_buf(uint8_t *data, size_t n)
{
    return randombytes(data, (uint64_t)n);
}
