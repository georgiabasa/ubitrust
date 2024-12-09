#ifndef __UBI_CREDENTIAL_H
#define __UBI_CREDENTIAL_H

#include <stdlib.h>
#include <stdint.h>

#include <ubi_common/macros.h>
#include <ubi_common/structs.h>

typedef struct ubi_make_credential_in
{
    struct ubi_buffer *secret;
    struct ubi_buffer *key_n;     
    struct ubi_buffer *key_e;     
    struct ubi_buffer *key_name;     
}ubi_make_credential_in;

typedef struct ubi_make_credential_out
{
    struct ubi_buffer *credential;     
    struct ubi_buffer *encrypted_secret;     
    struct ubi_buffer *auth_digest;     
    uint8_t iv[IV_SIZE];
}ubi_make_credential_out;

typedef struct ubi_activate_credential_in
{
    struct ubi_buffer *credential;     
    uint8_t iv[IV_SIZE];
    struct ubi_buffer *encrypted_random_secret;     
    struct ubi_buffer *auth_digest;     
    struct ubi_buffer *key_name;     
    struct ubi_buffer *key_d;     
    struct ubi_buffer *key_n;     
    struct ubi_buffer *key_e;     
    size_t secret_size;                                                                                                                 
}ubi_activate_credential_in;                                                                            
 
typedef struct ubi_activate_credential_out
{
    struct ubi_buffer *secret;     
}ubi_activate_credential_out;

void free_ubi_activate_credential_out(struct ubi_activate_credential_out *out);

void free_ubi_make_credential_out(struct ubi_make_credential_out *out);

int ubi_make_credential(struct ubi_make_credential_in *in, struct ubi_make_credential_out **out);

int ubi_activate_credential(struct ubi_activate_credential_in *in, struct ubi_activate_credential_out **out);

#endif