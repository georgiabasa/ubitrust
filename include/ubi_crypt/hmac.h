#ifndef __UBI_HMAC_H
#define __UBI_HMAC_H

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/structs.h>


typedef struct ubi_hmac_sha256_in {
    ubi_buffer *messages;       
    size_t messages_len;        
    ubi_buffer *key;            
} ubi_hmac_sha256_in;

 
typedef struct ubi_hmac_sha256_out {
    ubi_buffer *hmac_digest;   
} ubi_hmac_sha256_out;

void free_ubi_hmac_sha256_out(struct ubi_hmac_sha256_out *out);

int ubi_hmac_sha256(struct ubi_hmac_sha256_in *in, struct ubi_hmac_sha256_out **out);

#endif