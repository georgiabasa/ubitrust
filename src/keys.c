#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <ubi_crypt/ec.h>
#include <ubi_crypt/kdf.h>
#include <ubi_crypt/keys.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/aes.h>
#include <ubi_common/errors.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>


void free_ubi_create_attestation_key_out(struct ubi_create_attestation_key_out *out) {
    if (out) {
        if ((*out).seed) {
            if ((*out).seed->buffer) {
                free((*out).seed->buffer);
                (*out).seed->buffer = NULL;
            }
            free((*out).seed);
            (*out).seed = NULL;
        }
        if ((*out).hash_private_key) {
            if ((*out).hash_private_key->buffer) {
                free((*out).hash_private_key->buffer);
                (*out).hash_private_key->buffer = NULL;
            }
            free((*out).hash_private_key);
            (*out).hash_private_key = NULL;
        }
        if ((*out).name) {
            if ((*out).name->buffer) {
                free((*out).name->buffer);
                (*out).name->buffer = NULL;
            }
            free((*out).name);
            (*out).name = NULL;
        }
        if ((*out).public_key) {
            if ((*out).public_key->buffer) {
                free((*out).public_key->buffer);
                (*out).public_key->buffer = NULL;
            }
            free((*out).public_key);
            (*out).public_key = NULL;
        }
        free(out);
        out = NULL;
    }
}


void free_ubi_load_attestation_key_out(struct ubi_load_attestation_key_out *out) {
    if (out) {
        if ((*out).private_key) {
            if ((*out).private_key->buffer) {
                free((*out).private_key->buffer);
                (*out).private_key->buffer = NULL;
            }
            free((*out).private_key);
            (*out).private_key = NULL;
        }
        free(out);
        out = NULL;
    }
}

void free_ubi_create_migratable_key_out(struct ubi_create_migratable_key_out *out) {
    if (out) {
        if ((*out).encrypted_private_key) {
            if ((*out).encrypted_private_key->buffer) {
                free((*out).encrypted_private_key->buffer);
                (*out).encrypted_private_key->buffer = NULL;
            }
            free((*out).encrypted_private_key);
            (*out).encrypted_private_key = NULL;
        }
        if ((*out).hash_private_key) {
            if ((*out).hash_private_key->buffer) {
                free((*out).hash_private_key->buffer);
                (*out).hash_private_key->buffer = NULL;
            }
            free((*out).hash_private_key);
            (*out).hash_private_key = NULL;
        }
        if ((*out).name) {
            if ((*out).name->buffer) {
                free((*out).name->buffer);
                (*out).name->buffer = NULL;
            }
            free((*out).name);
            (*out).name = NULL;
        }
        if ((*out).public_key) {
            if ((*out).public_key->buffer) {
                free((*out).public_key->buffer);
                (*out).public_key->buffer = NULL;
            }
            free((*out).public_key);
            (*out).public_key = NULL;
        }
        free(out);
        out = NULL;
    }
}

void free_ubi_load_migratable_key_out(struct ubi_load_migratable_key_out *out) {
    if (out) {
        if ((*out).private_key) {
            if ((*out).private_key->buffer) {
                free((*out).private_key->buffer);
                (*out).private_key->buffer = NULL;
            }
            free((*out).private_key);
            (*out).private_key = NULL;
        }
        free(out);
        out = NULL;
    }
}

void free_ubi_compute_public_key_out(struct ubi_compute_public_key_out *out) {
    if (out) {
        if ((*out).public_key) {
            if ((*out).public_key->buffer) {
                free((*out).public_key->buffer);
                (*out).public_key->buffer = NULL;
            }
            free((*out).public_key);
            (*out).public_key = NULL;
        }
        free(out);
        out = NULL;
    }
}

int ubi_compute_public_key(struct ubi_compute_public_key_in *in, struct ubi_compute_public_key_out **out)
{
    size_t olen;
    int ret = UBI_SUCCESS;

    mbedtls_mpi *mpi_private_key = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_ecp_point *public_key = (mbedtls_ecp_point*)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_group *grp = NULL;
    mbedtls_mpi_init(mpi_private_key);
    mbedtls_ecp_point_init(public_key);

    ret = mbedtls_mpi_read_binary(mpi_private_key, (const uint8_t *)(*in).private_key->buffer, (*in).private_key->buffer_len);
    if (ret != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    switch ((*in).curve_type) {
        case BNP_256:
            ubi_get_ec_group_bnp256(&grp);
            break;
        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }
    if (grp == NULL)
    {   
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }
    

    ret = mbedtls_ecp_mul(grp, public_key, mpi_private_key, &(*grp).G, ubi_random_bytes, NULL);
    if (ret != 0) 
    {
        ret = UBI_ECP_MUL_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_compute_public_key_out *)calloc(1,sizeof(struct ubi_compute_public_key_out));
    (**out).public_key = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    ubi_get_ecp_size(public_key, &(**out).public_key->buffer_len);
    (**out).public_key->buffer = (uint8_t *)calloc((**out).public_key->buffer_len, sizeof(uint8_t));
    ret = mbedtls_ecp_point_write_binary(grp, public_key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, (**out).public_key->buffer, (**out).public_key->buffer_len);
    if (ret != 0) 
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(mpi_private_key);
    mbedtls_ecp_point_free(public_key);
    free_ubi_ecp_group(grp);
    free(grp);
    grp = NULL;
    free(mpi_private_key);
    mpi_private_key = NULL;
    free(public_key);
    public_key = NULL;

    return ret;
}


int ubi_create_attestation_key(struct ubi_create_attestation_key_in *in, struct ubi_create_attestation_key_out **out)
{
    uint8_t integrity[] = "INTEGRITY";
    uint8_t null[] = {0};
    int ret = UBI_SUCCESS;

    // Allocate space for the seed buffer
    *out = (struct ubi_create_attestation_key_out *)calloc(1,sizeof(struct ubi_create_attestation_key_out));
    if (*out == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).seed = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).seed == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    switch ((*in).curve_type)
    {
        case BNP_256:
            (**out).seed->buffer_len = SHA256_DIGEST_LENGTH;
            (**out).seed->buffer = (uint8_t *)calloc(1,(**out).seed->buffer_len * sizeof(uint8_t));
            if ((**out).seed->buffer == NULL)
            {
                ret = UBI_MEM_ERROR;
                goto cleanup;
            }
            break;

        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }

    // Generate random bytes for the seed
    if ((ret = ubi_random_bytes(NULL, (**out).seed->buffer, (**out).seed->buffer_len)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    // Allocate memory for KDF input and output structures
    struct ubi_buffer *integrity_label = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *null_context = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_kdf_in *kdf_in = (struct ubi_kdf_in *)calloc(1,sizeof(struct ubi_kdf_in));
    struct ubi_kdf_out *kdf_out = NULL;

    if (integrity_label == NULL || null_context == NULL || kdf_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Prepare the KDF input
    (*integrity_label).buffer = integrity;
    (*integrity_label).buffer_len = sizeof(integrity)-1;
    (*null_context).buffer = null;  
    (*null_context).buffer_len = sizeof(null);

    (*kdf_in).seed = (**out).seed;
    (*kdf_in).label = integrity_label;
    (*kdf_in).context_u = (*in).policy;
    (*kdf_in).context_v = null_context;
    (*kdf_in).key_bit_len = 256;

    // Call KDF function
    if ((ret = ubi_kdf_sha256(kdf_in, &kdf_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }


    // Allocate and hash the private key
    (**out).hash_private_key = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).hash_private_key == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    (**out).hash_private_key->buffer_len = SHA256_DIGEST_LENGTH;
    (**out).hash_private_key->buffer = (uint8_t *)calloc(1,SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    if ((**out).hash_private_key->buffer == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_sha256((*kdf_out).key->buffer, (*kdf_out).key->buffer_len, (**out).hash_private_key->buffer, 0);

    // Allocate memory for public key computation
    struct ubi_compute_public_key_in *pubkey_in = (struct ubi_compute_public_key_in *)calloc(1,sizeof(struct ubi_compute_public_key_in));
    struct ubi_compute_public_key_out *pubkey_out = NULL;

    if (pubkey_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Prepare inputs for computing the public key
    (*pubkey_in).curve_type = (*in).curve_type;
    (*pubkey_in).private_key = (*kdf_out).key;
    // Call function to compute the public key
    if ((ret = ubi_compute_public_key(pubkey_in, &pubkey_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    // Allocate and hash the public key to produce the "name"
    (**out).name = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).name == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    (**out).name->buffer_len = KEY_NAME_LENGTH;
    (**out).name->buffer = (uint8_t *)calloc(1,KEY_NAME_LENGTH * sizeof(uint8_t));
    if ((**out).name->buffer == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // Set the name prefix and hash the public key into it
    (**out).name->buffer[0] = RH_NULL;
    (**out).name->buffer[1] = ALG_SHA256;
    mbedtls_sha256((*pubkey_out).public_key->buffer, (*pubkey_out).public_key->buffer_len, &(**out).name->buffer[2], 0);
    (**out).public_key = (*pubkey_out).public_key;
cleanup:
    if (kdf_out != NULL){ free(kdf_out); kdf_out = NULL;}
    if (kdf_in != NULL) { free(kdf_in); kdf_in = NULL;}
    if (pubkey_in != NULL) {
        if((*pubkey_in).private_key != NULL) {
            if((*pubkey_in).private_key->buffer != NULL) { free((*pubkey_in).private_key->buffer); (*pubkey_in).private_key->buffer = NULL;}
            free((*pubkey_in).private_key); (*pubkey_in).private_key = NULL;
        }
        free(pubkey_in);
        pubkey_in = NULL;
    }

    if (pubkey_out != NULL) { free(pubkey_out); pubkey_out = NULL;}
    if (integrity_label != NULL) { free(integrity_label); integrity_label = NULL;}
    if (null_context != NULL) { free(null_context); null_context = NULL;}

    return ret;
}


int ubi_load_attestation_key(struct ubi_load_attestation_key_in *in, struct ubi_load_attestation_key_out **out) {

    int ret = UBI_SUCCESS;
    uint8_t integrity[] = "INTEGRITY";
    uint8_t null[] = {0};

    struct ubi_buffer *integrity_label = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *null_context = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_kdf_in *kdf_in = (struct ubi_kdf_in *)calloc(1,sizeof(struct ubi_kdf_in));
    struct ubi_kdf_out *kdf_out = NULL;

    if (integrity_label == NULL || null_context == NULL || kdf_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    // // Prepare the KDF input
    (*integrity_label).buffer = integrity;
    (*integrity_label).buffer_len = sizeof(integrity)-1;
    (*null_context).buffer = null;
    (*null_context).buffer_len = sizeof(null);

    (*kdf_in).seed = (*in).seed;
    (*kdf_in).label = integrity_label;
    (*kdf_in).context_u = (*in).policy;
    (*kdf_in).context_v = null_context;
    (*kdf_in).key_bit_len = 256;

    // // Call KDF function
    if ((ret = ubi_kdf_sha256(kdf_in, &kdf_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    // // Hash the private key to compare it with the provided hash
    uint8_t *hash_compare = (uint8_t *)calloc(SHA256_DIGEST_LENGTH,sizeof(uint8_t));
    mbedtls_sha256((*kdf_out).key->buffer, (*kdf_out).key->buffer_len, hash_compare, 0);
    
    // Compare the hash of the private key with the provided hashed private key
    if (memcmp((*in).hash_private_key->buffer, hash_compare, SHA256_DIGEST_LENGTH) != 0) {
        ret = UBI_LOAD_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_load_attestation_key_out *)calloc(1,sizeof(struct ubi_load_attestation_key_out));
    (**out).private_key = (*kdf_out).key;

cleanup:
    if(hash_compare != NULL) {free(hash_compare); hash_compare = NULL;}
    if (integrity_label != NULL) { free(integrity_label); integrity_label = NULL;}
    if (null_context != NULL) { free(null_context); null_context = NULL;}
    if (kdf_out != NULL) { free(kdf_out); kdf_out = NULL;}
    if (kdf_in != NULL) { free(kdf_in); kdf_in = NULL;}

    return ret;
}

int ubi_create_migratable_key(struct ubi_create_migratable_key_in *in, struct ubi_create_migratable_key_out **out)
{
    uint8_t integrity[] = "INTEGRITY";
    uint8_t null[] = {0};
    int ret = UBI_SUCCESS;
    *out = (struct ubi_create_migratable_key_out *)calloc(1,sizeof(struct ubi_create_migratable_key_out));

    struct ubi_buffer *seed = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if (seed == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    switch ((*in).curve_type)
    {
        case BNP_256:
           (*seed).buffer_len = SHA256_DIGEST_LENGTH;
           (*seed).buffer = (uint8_t *)calloc(1, (*seed).buffer_len);
            if ((*seed).buffer == NULL)
            {
                ret = UBI_MEM_ERROR;
                goto cleanup;
            }
            break;

        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }

    if ((ret = ubi_random_bytes(NULL,(*seed).buffer,(*seed).buffer_len)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    struct ubi_buffer *integrity_label = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *null_context = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_kdf_in *kdf_in = (struct ubi_kdf_in *)calloc(1,sizeof(struct ubi_kdf_in));
    struct ubi_kdf_out *kdf_out = NULL;

    if (integrity_label == NULL || null_context == NULL || kdf_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    (*integrity_label).buffer = integrity;    
    (*integrity_label).buffer_len = sizeof(integrity) - 1;

    (*null_context).buffer = null;    
    (*null_context).buffer_len = sizeof(null);

    (*kdf_in).seed = seed;
    (*kdf_in).label = integrity_label;
    (*kdf_in).context_u =(*in).policy;
    (*kdf_in).context_v = null_context;
    (*kdf_in).key_bit_len = 256;

    if ((ret = ubi_kdf_sha256(kdf_in, &kdf_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

   (**out).hash_private_key = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).hash_private_key == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

   (**out).hash_private_key->buffer_len = SHA256_DIGEST_LENGTH;
   (**out).hash_private_key->buffer = (uint8_t *)calloc(1,SHA256_DIGEST_LENGTH);
    if ((**out).hash_private_key->buffer == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_sha256((*kdf_out).key->buffer, (*kdf_out).key->buffer_len,(**out).hash_private_key->buffer, 0);

    struct ubi_compute_public_key_in *pubkey_in = (struct ubi_compute_public_key_in *)calloc(1,sizeof(struct ubi_compute_public_key_in));
    struct ubi_compute_public_key_out *pubkey_out = NULL;

    if (pubkey_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    (*pubkey_in).curve_type =(*in).curve_type;
    (*pubkey_in).private_key = (*kdf_out).key;

    if ((ret = ubi_compute_public_key(pubkey_in, &pubkey_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

   (**out).name = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).name == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

   (**out).name->buffer_len = KEY_NAME_LENGTH;
   (**out).name->buffer = (uint8_t *)calloc(1,KEY_NAME_LENGTH);
    if ((**out).name->buffer == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

   (**out).name->buffer[0] = RH_NULL;
   (**out).name->buffer[1] = ALG_SHA256;
    mbedtls_sha256((*pubkey_out).public_key->buffer, (*pubkey_out).public_key->buffer_len, &(**out).name->buffer[2], 0);


    (**out).public_key = (*pubkey_out).public_key; 
    if ((ret = ubi_random_bytes(NULL,(**out).iv, IV_SIZE)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    struct ubi_aes128_enc_in *enc_in = (struct ubi_aes128_enc_in *)calloc(1,sizeof(struct ubi_aes128_enc_in));
    struct ubi_aes128_enc_out *enc_out = NULL;

    if (enc_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    (*enc_in).plaintext = (*kdf_out).key;
    (*enc_in).key =(*in).policy; // Reuse the policy as the encryption key
    memcpy((*enc_in).iv,(**out).iv, IV_SIZE);

    if ((ret = ubi_aes_encrypt(enc_in, &enc_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    (**out).encrypted_private_key = enc_out->ciphertext;
cleanup:
    if (enc_in != NULL) { free(enc_in); enc_in = NULL;}
    if (enc_out != NULL) { free(enc_out); enc_out = NULL;}
    if (seed != NULL) {
        if((*seed).buffer != NULL) { free((*seed).buffer); (*seed).buffer = NULL;  }
        free(seed);
        seed = NULL;
    }
    if (kdf_out != NULL) { free(kdf_out); kdf_out = NULL;}
    if (kdf_in != NULL) { free(kdf_in); kdf_in = NULL;}
    if (pubkey_in != NULL)
    {
        if ((*pubkey_in).private_key != NULL)
        {
            if ((*pubkey_in).private_key->buffer != NULL) {free((*pubkey_in).private_key->buffer); (*pubkey_in).private_key->buffer = NULL;}
            free((*pubkey_in).private_key);
            (*pubkey_in).private_key = NULL;
        }
        free(pubkey_in);
        pubkey_in = NULL;   
    }
    if (pubkey_out != NULL){ free(pubkey_out); pubkey_out = NULL;}
    if (integrity_label != NULL) { free(integrity_label); integrity_label = NULL;}
    if (null_context != NULL) { free(null_context); null_context = NULL;}

    return ret;
}

int ubi_load_migratable_key(struct ubi_load_migratable_key_in *in, struct ubi_load_migratable_key_out **out)
{
    int ret = UBI_SUCCESS;
    *out = (struct ubi_load_migratable_key_out *)calloc(1,sizeof(struct ubi_load_migratable_key_out));  
    uint8_t *hash_compare = NULL;

    hash_compare = (uint8_t *)calloc(1,SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    if (hash_compare == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    struct ubi_aes128_dec_in *dec_in = (struct ubi_aes128_dec_in *)calloc(1,sizeof(struct ubi_aes128_dec_in));
    struct ubi_aes128_dec_out *dec_out = NULL;
    if (dec_in == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }



    (*dec_in).ciphertext =(*in).encrypted_private_key;
    (*dec_in).key =(*in).policy;  
    memcpy((*dec_in).iv,(*in).iv, IV_SIZE);

    if ((ret = ubi_aes_decrypt(dec_in, &dec_out)) != UBI_SUCCESS)
    {
        goto cleanup;
    }

    (**out).private_key = (*dec_out).plaintext;
    mbedtls_sha256((**out).private_key->buffer,(**out).private_key->buffer_len, hash_compare, 0);

    if (memcmp((*in).hash_private_key->buffer, hash_compare, SHA256_DIGEST_LENGTH) != 0)
    {
        ret = UBI_LOAD_ERROR;
        goto cleanup;
    }

cleanup:
    if (hash_compare != NULL) { free(hash_compare); hash_compare = NULL;}
    if (dec_in != NULL) { free(dec_in); dec_in = NULL;}
    if (dec_out != NULL) { free(dec_out); dec_out = NULL;}

    return ret;
}
