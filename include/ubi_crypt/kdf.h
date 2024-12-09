#ifndef __UBI_KDF_H
#define __UBI_KDF_H

#include <stdlib.h>
#include <stdint.h>


typedef struct ubi_kdf_in
{
    struct ubi_buffer *seed;
    struct ubi_buffer *label;
    struct ubi_buffer *context_u;
    struct ubi_buffer *context_v;
    size_t key_bit_len;
}ubi_kdf_in;
 
typedef struct ubi_kdf_out
{
    struct ubi_buffer *key;
}ubi_kdf_out;

void free_ubi_kdf_out(struct ubi_kdf_out *out);

int ubi_kdf_sha256(struct ubi_kdf_in *in, struct ubi_kdf_out **out);

#endif