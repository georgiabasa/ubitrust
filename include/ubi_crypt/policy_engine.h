#ifndef __UBI_POLICY_ENGINE_H__
#define __UBI_POLICY_ENGINE_H__

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>

typedef struct ubi_policy_session
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t session_handle[SESSION_HANDLE_SIZE];
    uint8_t session_digest[SHA256_DIGEST_LENGTH];
}ubi_policy_session;

typedef struct ubi_start_policy_session_out
{
    struct ubi_buffer *nonce;
    struct ubi_buffer *session_handle;
}ubi_start_policy_session_out;

typedef struct ubi_policy_signed_in
{
    struct ubi_buffer *session_handle;
    int curve_type;
    struct ubi_buffer *digest;
    struct ubi_buffer *signature_r;  
    struct ubi_buffer *signature_s; 
    struct ubi_buffer *public_key;
}ubi_policy_signed_in;

int alloc_ubi_start_policy_session_out(struct ubi_start_policy_session_out **out);

int free_ubi_start_policy_session_out(struct ubi_start_policy_session_out *out);

int ubi_start_policy_session(void *in, struct ubi_start_policy_session_out **out);

int ubi_policy_signed(struct ubi_policy_signed_in *in, void *out);

int ubi_get_policy_digest(ubi_buffer *in, ubi_buffer **out);

#endif