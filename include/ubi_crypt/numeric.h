#ifndef __UBI_NUMERIC_H
#define __UBI_NUMERIC_H

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/structs.h>

typedef struct ubi_mod_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer *input;
} ubi_mod_in;

typedef struct ubi_mod_out
{
    struct ubi_buffer *output;
} ubi_mod_out;
int free_ubi_mod_out(struct ubi_mod_out *out);

int ubi_mod(struct ubi_mod_in *in, struct ubi_mod_out **out);

#endif