#ifndef __UBI_HASH_H__
#define __UBI_HASH_H__

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


typedef struct ubi_sha_in
{
    struct ubi_buffer *messages;
    size_t messages_len;
}ubi_sha_in;

typedef struct ubi_sha_out
{
    struct ubi_buffer *digest;
}ubi_sha_out;

void free_ubi_sha_out(struct ubi_sha_out *out);

int ubi_sha256(struct ubi_sha_in *in, struct ubi_sha_out **out);


#endif