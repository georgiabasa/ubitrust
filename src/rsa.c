#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <ubi_crypt/rsa.h>
#include <ubi_crypt/rand.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>


void free_ubi_rsa_encrypt_out(struct ubi_rsa_encrypt_out *encrypt_out) {
    if (encrypt_out) {
        if (encrypt_out->ciphertext) {
            if (encrypt_out->ciphertext->buffer) {
                free(encrypt_out->ciphertext->buffer);
                encrypt_out->ciphertext->buffer = NULL;
            }
            free(encrypt_out->ciphertext);
            encrypt_out->ciphertext = NULL;
        }
        free(encrypt_out);
        encrypt_out = NULL;
    }
}

void free_ubi_rsa_decrypt_out(struct ubi_rsa_decrypt_out *decrypt_out) {
    if (decrypt_out) {
        if (decrypt_out->plaintext) {
            if (decrypt_out->plaintext->buffer) {
                free(decrypt_out->plaintext->buffer);
                decrypt_out->plaintext->buffer = NULL;  
            }
            free(decrypt_out->plaintext);
            decrypt_out->plaintext = NULL;
        }
        free(decrypt_out);
        decrypt_out = NULL;
    }
}
// Function to encrypt data using a public key with OAEP padding
int ubi_rsa_encrypt(struct ubi_rsa_encrypt_in *in, struct ubi_rsa_encrypt_out **out)
{
    int ret = UBI_SUCCESS;
    *out = (struct ubi_rsa_encrypt_out*)calloc(1,sizeof(struct ubi_rsa_encrypt_out));
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context*)calloc(1,sizeof(mbedtls_rsa_context));
    mbedtls_mpi *n = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *e = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));

    mbedtls_rsa_init(rsa);
    mbedtls_mpi_init(n);
    mbedtls_mpi_init(e);

    //Setting up public key
    if((ret = mbedtls_mpi_read_binary(n, (*in).public_key->buffer, (*in).public_key->buffer_len)) != 0 ||
        (ret = mbedtls_mpi_read_binary(e, (*in).public_key_exponent->buffer, (*in).public_key_exponent->buffer_len)) !=0 )
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if((ret = mbedtls_rsa_import(rsa, n, NULL, NULL, NULL, e) != 0)||
        (ret = mbedtls_rsa_complete(rsa) != 0))
    {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    // Set padding for encryption (OAEP)
    if((ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256)) != 0){
        ret = UBI_PADDING_ERROR;
        goto cleanup;
    }
    (**out).ciphertext = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).ciphertext->buffer_len = mbedtls_rsa_get_len(rsa);
    (**out).ciphertext->buffer = (uint8_t *)calloc((**out).ciphertext->buffer_len, sizeof(uint8_t));
    // Encrypt the input data
    if ((ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(rsa, ubi_random_bytes, NULL, (*in).plaintext->buffer_len, (*in).plaintext->buffer, (**out).ciphertext->buffer)) != 0) 
    {
        goto cleanup;
    }

    

cleanup:
    mbedtls_mpi_free(n);
    mbedtls_mpi_free(e);
    mbedtls_rsa_free(rsa);
    free(rsa);
    rsa = NULL;
    free(n);
    n = NULL;
    free(e);
    e = NULL;
    return ret;
}

// Function to decrypt data using a private key with OAEP padding
int ubi_rsa_decrypt(struct ubi_rsa_decrypt_in *in, struct ubi_rsa_decrypt_out **out)
{
    int ret = UBI_SUCCESS;
    *out = (struct ubi_rsa_decrypt_out*)calloc(1,sizeof(struct ubi_rsa_decrypt_out));   
    uint8_t *rsa_temp_buffer = NULL;
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context*)calloc(1,sizeof(mbedtls_rsa_context));
    mbedtls_mpi *d = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *n = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *e = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));

    mbedtls_rsa_init(rsa);
    mbedtls_mpi_init(e);
    mbedtls_mpi_init(n);
    mbedtls_mpi_init(d);

    //Setting up private key for decryption
    if((ret = mbedtls_mpi_read_binary(n, (*in).rsa_modulus->buffer, (*in).rsa_modulus->buffer_len)) != 0 ||
        (ret = mbedtls_mpi_read_binary(d, (*in).private_exponent->buffer, (*in).private_exponent->buffer_len)) != 0||
        (ret =mbedtls_mpi_read_binary(e, (*in).public_key_exponent->buffer, (*in).public_key_exponent->buffer_len)) != 0)
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_rsa_import(rsa, n, NULL, NULL, d, e) != 0)||
        (ret = mbedtls_rsa_complete(rsa) != 0))
    {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }


    // Set padding for decryption (OAEP)
    if((ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256)) != 0){
        ret = UBI_PADDING_ERROR;
        goto cleanup;
    }

    // Decrypt the input data
    (**out).plaintext = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    rsa_temp_buffer = (uint8_t *)calloc(1,rsa->MBEDTLS_PRIVATE(len));
    if ((ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(rsa, ubi_random_bytes, NULL, &(**out).plaintext->buffer_len, (*in).ciphertext->buffer, rsa_temp_buffer, rsa->MBEDTLS_PRIVATE(len))) != 0) 
    {
        goto cleanup;
    }
    (**out).plaintext->buffer = (uint8_t *)calloc((**out).plaintext->buffer_len, sizeof(uint8_t));
    if ((ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(rsa, ubi_random_bytes, NULL, &(**out).plaintext->buffer_len, (*in).ciphertext->buffer, (**out).plaintext->buffer, (**out).plaintext->buffer_len)) != 0) 
    {
        goto cleanup;
    }

cleanup:
    if(e) {mbedtls_mpi_free(e); free(e); e = NULL;} 
    if(n) {mbedtls_mpi_free(n); free(n); n = NULL;} 
    if(d) {mbedtls_mpi_free(d); free(d); d = NULL;} 
    if(rsa) {mbedtls_rsa_free(rsa); free(rsa); rsa = NULL;}
    if(rsa_temp_buffer) {free(rsa_temp_buffer); rsa_temp_buffer = NULL;}
    return ret;
}