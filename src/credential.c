#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h> 

#include <ubi_crypt/rand.h>
#include <ubi_crypt/credential.h>
#include <ubi_crypt/hmac.h>
#include <ubi_crypt/kdf.h>
#include <ubi_crypt/aes.h>
#include <ubi_crypt/rsa.h>


void free_ubi_make_credential_out(struct ubi_make_credential_out *out) {
    if (out) {
        if ((*out).credential) {
            if ((*out).credential->buffer) {
                free((*out).credential->buffer);
                (*out).credential->buffer = NULL;
            }
            free((*out).credential);
            (*out).credential = NULL;
        }
        if ((*out).encrypted_secret) {
            if ((*out).encrypted_secret->buffer) {
                free((*out).encrypted_secret->buffer);
                (*out).encrypted_secret->buffer = NULL;
            }
            free((*out).encrypted_secret);
            (*out).encrypted_secret = NULL;
        }
        if ((*out).auth_digest) {
            if ((*out).auth_digest->buffer) {
                free((*out).auth_digest->buffer);
                (*out).auth_digest->buffer = NULL;
            }
            free((*out).auth_digest);
            (*out).auth_digest = NULL;
        }
        free(out);
        out = NULL;
    }
}

void free_ubi_activate_credential_out(struct ubi_activate_credential_out *out) {
    if (out) {
        if ((*out).secret) {
            if ((*out).secret->buffer) {
                free((*out).secret->buffer);
                (*out).secret->buffer = NULL;
            }
            free((*out).secret);
            (*out).secret = NULL;
        }
        free(out);
        out = NULL;
    }
}


int ubi_make_credential(struct ubi_make_credential_in *in, struct ubi_make_credential_out **out)
{
    int ret = UBI_SUCCESS;
    uint8_t *random_secret = calloc(1,SHA256_DIGEST_LENGTH);
    uint8_t integrity[10] = {"INTEGRITY\0"};

    *out = (struct ubi_make_credential_out*)calloc(1,sizeof(struct ubi_make_credential_out));
    struct ubi_buffer *enc_key = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_aes128_enc_in *aes_in = (struct ubi_aes128_enc_in*)calloc(1,sizeof(struct ubi_aes128_enc_in));
    struct ubi_aes128_enc_out *aes_out = NULL;

    struct ubi_buffer *seed = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *label = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *context_v = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_kdf_in *kdf_in = (struct ubi_kdf_in*)calloc(1,sizeof(struct ubi_kdf_in));
    struct ubi_kdf_out *kdf_out = NULL;
    
    struct ubi_hmac_sha256_in *hmac_in = (struct ubi_hmac_sha256_in*)calloc(1,sizeof(struct ubi_hmac_sha256_in));
    struct ubi_hmac_sha256_out *hmac_out = NULL;

    struct ubi_buffer *input = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_rsa_encrypt_in *rsa_in = (struct ubi_rsa_encrypt_in*)calloc(1,sizeof(struct ubi_rsa_encrypt_in));
    struct ubi_rsa_encrypt_out *rsa_out = NULL;


    if((ret = ubi_random_bytes(NULL, random_secret, SHA256_DIGEST_LENGTH)) != UBI_SUCCESS)
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }
    if((ret = ubi_random_bytes(NULL, (**out).iv, IV_SIZE)) != UBI_SUCCESS)
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }
    ;
    
    // AES ENCRYPTION
    (*enc_key).buffer = random_secret;
    (*enc_key).buffer_len = AES_KEY_SIZE;
    
    (*aes_in).plaintext = (*in).secret;
    (*aes_in).key = enc_key;
    memcpy((*aes_in).iv, (**out).iv, IV_SIZE);

    if((ret = ubi_aes_encrypt(aes_in, &aes_out) != UBI_SUCCESS))
    {
        ret = UBI_AES_ERROR;
        goto cleanup;
    }   

    (**out).credential = aes_out->ciphertext;

    // KDF
    (*seed).buffer = random_secret;

    (*seed).buffer_len = SHA256_DIGEST_LENGTH;
    (*label).buffer = integrity;    
    (*label).buffer_len = 10;
    (*context_v).buffer = NULL;
    (*context_v).buffer_len = 0;
    size_t key_len_bits = 8 * SHA256_DIGEST_LENGTH; 

    (*kdf_in).seed = seed;
    (*kdf_in).label = label;
    (*kdf_in).context_u = (*in).key_name;
    (*kdf_in).context_v = context_v;
    (*kdf_in).key_bit_len = key_len_bits;

    if(( ret = ubi_kdf_sha256(kdf_in, &kdf_out)) != UBI_SUCCESS)
    {
        ret = UBI_KDF_ERROR;
        goto cleanup;
    }   

    // HMAC

    (*hmac_in).messages_len = 1;

    (*hmac_in).messages = (*in).secret;
    (*hmac_in).key = (*kdf_out).key;

    if((ret = ubi_hmac_sha256(hmac_in, &hmac_out)) != UBI_SUCCESS)
    {
        ret = UBI_HMAC_ERROR;
        goto cleanup;
    }   

    // RSA ENCRYPTION

    (*input).buffer = random_secret;
    (*input).buffer_len = SHA256_DIGEST_LENGTH;
    
    (*rsa_in).plaintext = input;
    (*rsa_in).public_key = (*in).key_n;
    (*rsa_in).public_key_exponent = (*in).key_e;

    if((ret = ubi_rsa_encrypt(rsa_in, &rsa_out)) != UBI_SUCCESS)
    {
        ret = UBI_RSA_ENC_ERROR;
        goto cleanup;
    }   

    (**out).encrypted_secret = (*rsa_out).ciphertext;
    (**out).auth_digest = (*hmac_out).hmac_digest;


    cleanup:
        free_ubi_kdf_out(kdf_out);     
        if (rsa_out != NULL) { free(rsa_out); rsa_out = NULL;}
        if (rsa_in != NULL) { free(rsa_in); rsa_in = NULL;}
        if (input != NULL) { free(input); input = NULL;}
        if (hmac_out != NULL) { free(hmac_out); hmac_out = NULL;}
        if (hmac_in != NULL) { free(hmac_in); hmac_in = NULL;}
        if (kdf_in != NULL) { free(kdf_in); kdf_in = NULL;}
        if (context_v != NULL) { free(context_v); context_v = NULL;}
        if (label != NULL) {free(label); label = NULL;}
        if (seed != NULL) { free(seed); seed = NULL;}
        if (enc_key != NULL) { free(enc_key); enc_key = NULL;}
        if (aes_out != NULL) { free(aes_out); aes_out = NULL;}
        if (aes_in != NULL) { free(aes_in); aes_in = NULL;}
        if (random_secret != NULL) { free(random_secret); random_secret = NULL;}

    return ret;
}

int ubi_activate_credential(struct ubi_activate_credential_in *in, struct ubi_activate_credential_out **out)
{
    int ret = UBI_SUCCESS;
    uint8_t integrity[10] = {"INTEGRITY\0"};
    *out = (struct ubi_activate_credential_out*)calloc(1,sizeof(struct ubi_activate_credential_out));

    struct ubi_aes128_dec_in *aes_in = (struct ubi_aes128_dec_in*)calloc(1,sizeof(struct ubi_aes128_dec_in));
    struct ubi_aes128_dec_out *aes_out = NULL;

    struct ubi_buffer *label = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *context_v = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_kdf_in *kdf_in = (struct ubi_kdf_in*)calloc(1,sizeof(struct ubi_kdf_in));
    struct ubi_kdf_out *kdf_out = NULL;
    
    struct ubi_hmac_sha256_in *hmac_in = (struct ubi_hmac_sha256_in*)calloc(1,sizeof(struct ubi_hmac_sha256_in));
    struct ubi_hmac_sha256_out *hmac_out = NULL;

    struct ubi_rsa_decrypt_in *rsa_in = (struct ubi_rsa_decrypt_in*)calloc(1,sizeof(struct ubi_rsa_decrypt_in));
    struct ubi_rsa_decrypt_out *rsa_out = NULL;


    (*rsa_in).ciphertext = (*in).encrypted_random_secret;
    (*rsa_in).private_exponent = (*in).key_d;
    (*rsa_in).public_key_exponent = (*in).key_e;
    (*rsa_in).rsa_modulus = (*in).key_n;

    if((ret = ubi_rsa_decrypt(rsa_in, &rsa_out)) != UBI_SUCCESS)
    {
        ret = UBI_RSA_DEC_ERROR;
        goto cleanup;
    }   


    
    (*aes_in).ciphertext = (*in).credential;
    (*aes_in).key = (*rsa_out).plaintext; 
    memcpy((*aes_in).iv, (*in).iv, IV_SIZE);

    if((ret = ubi_aes_decrypt(aes_in, &aes_out)) != UBI_SUCCESS)
    {
        ret = UBI_AES_ERROR;
        goto cleanup;
    }

    (*label).buffer = integrity;

    (*label).buffer_len = 10;
    (*context_v).buffer = NULL;
    (*context_v).buffer_len = 0;
    size_t key_len_bits = 8 * SHA256_DIGEST_LENGTH; 

    (*kdf_in).seed = (*rsa_out).plaintext;
    (*kdf_in).label = label;
    (*kdf_in).context_u = (*in).key_name;
    (*kdf_in).context_v = context_v;
    (*kdf_in).key_bit_len = key_len_bits;

    if((ret = ubi_kdf_sha256(kdf_in, &kdf_out)) != UBI_SUCCESS)
    {
        ret = UBI_KDF_ERROR;
        goto cleanup;
    }   


    (*hmac_in).messages_len = 1;

    (*hmac_in).key = (*kdf_out).key;
    (*hmac_in).messages = (*aes_out).plaintext;   

    if((ret = ubi_hmac_sha256(hmac_in, &hmac_out) != UBI_SUCCESS)){
        ret = UBI_HMAC_ERROR;
        goto cleanup;
    }   
    
    (**out).secret = (*aes_out).plaintext;
 

    if(memcmp((*hmac_out).hmac_digest->buffer, (*in).auth_digest->buffer, (*in).auth_digest->buffer_len))
    {
        ret = UBI_AUTHENTICATION_ERROR;
        goto cleanup;   
    }      
       

    cleanup:
        if (context_v != NULL) {
            if ((*context_v).buffer != NULL) {
                free((*context_v).buffer);
                (*context_v).buffer = NULL;
            }
            free(context_v);
            context_v = NULL;
        } 
        if(hmac_out != NULL) {
            if((*hmac_out).hmac_digest != NULL) {
                if((*hmac_out).hmac_digest->buffer != NULL) {
                    free((*hmac_out).hmac_digest->buffer);
                    (*hmac_out).hmac_digest->buffer = NULL;
                }
                free((*hmac_out).hmac_digest);
                (*hmac_out).hmac_digest = NULL;
            }
            free(hmac_out);
            hmac_out = NULL;
        }
        if (kdf_out != NULL) {
            if(kdf_out->key != NULL) {
                if(kdf_out->key->buffer != NULL) {
                    free(kdf_out->key->buffer);
                    kdf_out->key->buffer = NULL;
                }
                free(kdf_out->key);
                kdf_out->key = NULL;
            }
            free(kdf_out);
            kdf_out = NULL;
        }
        if (rsa_out != NULL) { free_ubi_rsa_decrypt_out(rsa_out); rsa_out = NULL;}   
        if (rsa_in != NULL) { free(rsa_in); rsa_in = NULL;}
        if(hmac_in != NULL) { free(hmac_in); hmac_in = NULL;}        
        if (kdf_in != NULL) { free(kdf_in); kdf_in = NULL;}        
        if (label != NULL) { free(label); label = NULL;}
        if (aes_out != NULL) { free(aes_out); aes_out = NULL;}
        if (aes_in != NULL) { free(aes_in); aes_in = NULL;}

    return ret; 
}