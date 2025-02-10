#ifndef __UBI_RANDOM_H
#define __RANDOM_H

#include <stdlib.h>
#include <stdint.h>



typedef struct ubi_random_bytes_mod_in
{
    size_t bytes_num;
    struct ubi_buffer *mod_order;
}ubi_random_bytes_mod_in;
 
typedef struct ubi_random_bytes_mod_out
{
    struct ubi_buffer *random_bytes_mod;
}ubi_random_bytes_mod_out;

typedef struct ubi_constant_time_rng_in{
    int i; 
    int k; 
    int N; 
} ubi_constant_time_rng_in;

typedef struct ubi_constant_time_rng_out{
    int random_value; 
    int status;       
} ubi_constant_time_rng_out;

int free_ubi_random_bytes_mod_out(struct ubi_random_bytes_mod_out *out);

int ubi_random_bytes(void *p_rng, unsigned char *output, size_t bytes_num);

int ubi_random_bytes_mod(struct ubi_random_bytes_mod_in *in, struct ubi_random_bytes_mod_out **out);

int ubi_constant_time_rng(struct ubi_constant_time_rng_in *in, struct ubi_constant_time_rng_out *out);
#endif