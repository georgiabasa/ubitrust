#ifndef UBI_RSA_H
#define UBI_RSA_H

#include <stdlib.h>
#include <stdint.h>

#include <ubi_common/macros.h>
#include <ubi_common/structs.h>

typedef struct ubi_rsa_encrypt_in
{
    struct ubi_buffer *public_key;
    struct ubi_buffer *public_key_exponent;
    struct ubi_buffer *plaintext;
}ubi_rsa_encrypt_in;

typedef struct ubi_rsa_encrypt_out
{
    struct ubi_buffer *ciphertext;
}ubi_rsa_encrypt_out;

typedef struct ubi_rsa_decrypt_in
{
    struct ubi_buffer *private_exponent;
    struct ubi_buffer *rsa_modulus;
    struct ubi_buffer *public_key_exponent;
    struct ubi_buffer *ciphertext;
}ubi_rsa_decrypt_in;
 
typedef struct ubi_rsa_decrypt_out
{
    struct ubi_buffer *plaintext;
}ubi_rsa_decrypt_out;

void free_ubi_rsa_decrypt_out(struct ubi_rsa_decrypt_out *decrypt_out);
void free_ubi_rsa_encrypt_out(struct ubi_rsa_encrypt_out *encrypt_out);
int ubi_rsa_encrypt(struct ubi_rsa_encrypt_in *in, struct ubi_rsa_encrypt_out **out);
int ubi_rsa_decrypt(struct ubi_rsa_decrypt_in *in, struct ubi_rsa_decrypt_out **out);

#endif