#ifndef __UBI_ECDSA_H__
#define __UBI_ECDSA_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct ubi_ecdsa_sign_in
{
    int curve_type;
    struct ubi_buffer *private_key;  
    struct ubi_buffer *digest;       
} ubi_ecdsa_sign_in;

typedef struct ubi_ecdsa_sign_out
{
    struct ubi_buffer *signature_r;  
    struct ubi_buffer *signature_s;  
} ubi_ecdsa_sign_out;

typedef struct ubi_ecdsa_verify_in
{
    int curve_type;
    struct ubi_buffer *public_key;   
    struct ubi_buffer *digest;      
    struct ubi_buffer *signature_r;  
    struct ubi_buffer *signature_s;  
} ubi_ecdsa_verify_in;

typedef struct ubi_ecdsa_verify_out
{
    size_t verification_status;

}ubi_ecdsa_verify_out;

void free_ubi_ecdsa_sign_out(struct ubi_ecdsa_sign_out *sign_out);

int ubi_ecdsa_sign(struct ubi_ecdsa_sign_in *in, struct ubi_ecdsa_sign_out **out);


int ubi_ecdsa_verify(struct ubi_ecdsa_verify_in *in, struct ubi_ecdsa_verify_out *out);

#endif

