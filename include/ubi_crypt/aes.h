#ifndef __UBI_AES_H__
#define __UBI_AES_H__

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>

typedef struct ubi_aes128_enc_in {
    struct ubi_buffer *plaintext;
    struct ubi_buffer *key;
    uint8_t iv[IV_SIZE];
} ubi_aes128_enc_in;

typedef struct ubi_aes128_enc_out {
    struct ubi_buffer *ciphertext;
    uint8_t iv[IV_SIZE];
} ubi_aes128_enc_out;

typedef struct ubi_aes128_dec_in {
    struct ubi_buffer *ciphertext;
    struct ubi_buffer *key;
    uint8_t iv[IV_SIZE];
} ubi_aes128_dec_in;

typedef struct ubi_aes128_dec_out {
    struct ubi_buffer *plaintext;
} ubi_aes128_dec_out;


void free_ubi_aes128_enc_out(struct ubi_aes128_enc_out *enc_out);

void free_ubi_aes128_dec_out(struct ubi_aes128_dec_out *dec_out);   

int ubi_aes_encrypt(struct ubi_aes128_enc_in *in, struct ubi_aes128_enc_out **out);

int ubi_aes_decrypt(struct ubi_aes128_dec_in *in, struct ubi_aes128_dec_out **out);

#endif