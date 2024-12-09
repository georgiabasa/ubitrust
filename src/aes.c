#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <ubi_crypt/aes.h>
#include <ubi_common/errors.h>



void free_ubi_aes128_enc_out(struct ubi_aes128_enc_out *enc_out) {
    if (enc_out) {
        if (enc_out->ciphertext) {
            if (enc_out->ciphertext->buffer) {
                free(enc_out->ciphertext->buffer);
                enc_out->ciphertext->buffer = NULL;
            }
            free(enc_out->ciphertext);
            enc_out->ciphertext = NULL; 
        }
        free(enc_out);
        enc_out = NULL;
    }
}

void free_ubi_aes128_dec_out(struct ubi_aes128_dec_out *dec_out) {
    if (dec_out) {
        if (dec_out->plaintext) {
            if (dec_out->plaintext->buffer) {
                free(dec_out->plaintext->buffer);
                dec_out->plaintext->buffer = NULL;
            }
            free(dec_out->plaintext);
            dec_out->plaintext = NULL;
        }
        free(dec_out);
        dec_out = NULL;
    }
}

// Encrypt function with careful memory management
int ubi_aes_encrypt(struct ubi_aes128_enc_in *in, struct ubi_aes128_enc_out **out)
{
    int ret = UBI_SUCCESS;
    mbedtls_aes_context *aes_context = NULL;
    uint8_t *padded_data = NULL;

    aes_context = (mbedtls_aes_context *)calloc(1,sizeof(mbedtls_aes_context));
    if (!aes_context) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Copy IV to output structure
    *out = (struct ubi_aes128_enc_out *)calloc(1,sizeof(struct ubi_aes128_enc_out));
    memcpy((**out).iv,(*in).iv, IV_SIZE);

    mbedtls_aes_init(aes_context);

    if (mbedtls_aes_setkey_enc(aes_context,(*in).key->buffer, AES_KEY_SIZE * 8) != 0) 
    {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    // Calculate padding length and total length after padding
    size_t padding_length = IV_SIZE - ((*in).plaintext->buffer_len % IV_SIZE);
    size_t padded_data_length =(*in).plaintext->buffer_len + padding_length;

    // Allocate memory for padded data
    padded_data = (uint8_t *)calloc(1,padded_data_length);
    if (!padded_data) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Copy plaintext data and apply padding
    memcpy(padded_data,(*in).plaintext->buffer,(*in).plaintext->buffer_len);
    memset(padded_data +(*in).plaintext->buffer_len, (int)padding_length, padding_length);

    // Allocate memory for ciphertext
   (**out).ciphertext = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if (!(**out).ciphertext) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

   (**out).ciphertext->buffer = (uint8_t *)calloc(1,padded_data_length);
    if (!(**out).ciphertext->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Perform AES CBC encryption
    if (mbedtls_aes_crypt_cbc(aes_context, MBEDTLS_AES_ENCRYPT, padded_data_length,(*in).iv, padded_data,(**out).ciphertext->buffer) != 0) 
    {
        ret = UBI_AES_ERROR;
        goto cleanup;
    }

    // Set ciphertext length
   (**out).ciphertext->buffer_len = padded_data_length;

cleanup:
    if (padded_data) {free(padded_data); padded_data = NULL;}
    if (aes_context) {mbedtls_aes_free(aes_context); free(aes_context); aes_context = NULL;}
    return ret;
}


int ubi_aes_decrypt(struct ubi_aes128_dec_in *in, struct ubi_aes128_dec_out **out)
{
    int ret = UBI_SUCCESS;
    mbedtls_aes_context *aes_context = NULL;
    uint8_t *decrypted_data = NULL;

    // Initialize AES context
    aes_context = (mbedtls_aes_context *)calloc(1,sizeof(mbedtls_aes_context));
    if (!aes_context) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_aes_init(aes_context);

    // Set decryption key
    if (mbedtls_aes_setkey_dec(aes_context,(*in).key->buffer, AES_KEY_SIZE * 8) != 0) 
    {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    // Allocate memory for decrypted data
    decrypted_data = (uint8_t *)calloc(1,(*in).ciphertext->buffer_len);
    if (!decrypted_data) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Perform AES CBC decryption
    if (mbedtls_aes_crypt_cbc(aes_context, MBEDTLS_AES_DECRYPT,(*in).ciphertext->buffer_len,(*in).iv,(*in).ciphertext->buffer, decrypted_data) != 0) 
    {
        ret = UBI_AES_ERROR;
        goto cleanup;
    }

    // Validate and remove padding
    size_t padding_length = decrypted_data[(*in).ciphertext->buffer_len - 1];
    if (padding_length < 1 || padding_length > IV_SIZE) 
    {
        ret = UBI_PADDING_ERROR;
        goto cleanup;
    }

    for (size_t i = 0; i < padding_length; i++) 
    {
        if (decrypted_data[(*in).ciphertext->buffer_len - 1 - i] != padding_length) 
        {
            ret = UBI_PADDING_ERROR;
            goto cleanup;
        }
    }

    // Set plaintext length and allocate memory for the plaintext
    size_t plaintext_len =(*in).ciphertext->buffer_len - padding_length;
    *out = (struct ubi_aes128_dec_out *)calloc(1,sizeof(struct ubi_aes128_dec_out));
   (**out).plaintext = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if (!(**out).plaintext) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
   (**out).plaintext->buffer = (uint8_t *)calloc(1,plaintext_len);
    if (!(**out).plaintext->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Copy the decrypted plaintext data
    memcpy((**out).plaintext->buffer, decrypted_data, plaintext_len);
   (**out).plaintext->buffer_len = plaintext_len;

cleanup:
    if (decrypted_data) {free(decrypted_data); decrypted_data = NULL;}
    if (aes_context) {mbedtls_aes_free(aes_context); free(aes_context); aes_context = NULL;}
    return ret;
}
