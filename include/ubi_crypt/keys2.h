#ifndef __UBI_KEYS2_H__
#define __UBI_KEYS2_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct ubi_create_key2_in
{
    int curve_type;
}ubi_create_key2_in;

typedef struct ubi_create_key2_out
{
    struct ubi_buffer *private_key;
    struct ubi_buffer *public_key;
    struct ubi_buffer *generator;
}ubi_create_key2_out;
    

int free_ubi_create_key2_out(struct ubi_create_key2_out *out);

int ubi_create_key2(struct ubi_create_key2_in *in, struct ubi_create_key2_out **out);


#endif // __UBI_KEYS2_H__