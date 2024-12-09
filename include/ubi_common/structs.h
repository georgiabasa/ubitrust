#ifndef __UBI_STRUCTS_H__
#define __UBI_STRUCTS_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct ubi_buffer
{
    uint8_t *buffer;
    size_t buffer_len;
}ubi_buffer;

#endif