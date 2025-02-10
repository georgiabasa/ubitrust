#ifndef __UBI_SCHNORR_H__
#define __UBI_SCHNORR_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct ubi_schnorr_sign_in
{
    int curve_type;
    struct ubi_buffer *private_key;  
    struct ubi_buffer *digest;       
} ubi_schnorr_sign_in;

typedef struct ubi_schnorr_sign_out
{
    struct ubi_buffer *signature_r;  
    struct ubi_buffer *signature_s;  
} ubi_schnorr_sign_out;

typedef struct ubi_schnorr_verify_in
{
    int curve_type;
    struct ubi_buffer *public_key;   
    struct ubi_buffer *digest;      
    struct ubi_buffer *signature_r;  
    struct ubi_buffer *signature_s;  
} ubi_schnorr_verify_in;

typedef struct ubi_schnorr_verify_out
{
    size_t verification_status;

}ubi_schnorr_verify_out;

int free_ubi_schnorr_signature_out(struct ubi_schnorr_sign_out *out);

int ubi_schnorr_sign(struct ubi_schnorr_sign_in *in, struct ubi_schnorr_sign_out **out);

int ubi_schnorr_verify(struct ubi_schnorr_verify_in *in, struct ubi_schnorr_verify_out *out);

#endif

