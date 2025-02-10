#include <stdint.h>
#include <stdlib.h>

#include <ecp2_FP256BN.h>
#include <big_256_56.h>

#include <ubi_crypt/keys2.h>
#include <ubi_crypt/rand.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


int ubi_create_key_fp256_key2(struct ubi_create_key2_in *in, struct ubi_create_key2_out **out);

int ubi_create_key_fp256_key2(struct ubi_create_key2_in *in, struct ubi_create_key2_out **out){
    int ret = UBI_SUCCESS;
    ECP2_FP256BN *core_generator = NULL;
    octet *octet_generator = NULL;
    BIG_256_56 *core_secret = NULL;
    octet *octet_public = NULL;
    uint8_t BNP256_ORDER[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71,
                            0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C,
                            0xD1, 0x0B, 0x50, 0x0D};
    struct ubi_buffer ubi_BNP256_ORDER = {BNP256_ORDER, sizeof(BNP256_ORDER)};
    struct ubi_random_bytes_mod_in private_key_in = {32, &ubi_BNP256_ORDER};
    struct ubi_random_bytes_mod_out *private_key_out = NULL;
    ret = ubi_random_bytes_mod(&private_key_in, &private_key_out);
    if(ret != UBI_SUCCESS){
        goto cleanup;
    }
    core_generator = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    if(core_generator == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if(!ECP2_FP256BN_generator(core_generator)){
        ret = UBI_EC2_GENERATOR_ERROR;
        goto cleanup;
    }
    octet_generator = (octet *)calloc(1,sizeof(octet));
    if(octet_generator == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (*octet_generator).val = (char *)calloc(ECP2_FP256BN_LENGTH, sizeof(char));
    ECP2_FP256BN_toOctet(octet_generator, core_generator, false);
    core_secret = (BIG_256_56 *)calloc(1,sizeof(BIG_256_56));
    if(core_secret == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    BIG_256_56_fromBytes(*core_secret, (char *)(*private_key_out).random_bytes_mod->buffer);
    ECP2_FP256BN_mul(core_generator, *core_secret);
    octet_public = (octet *)calloc(1,sizeof(octet));
    if(octet_public == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (*octet_public).val = (char *)calloc(ECP2_FP256BN_LENGTH, sizeof(char));
    ECP2_FP256BN_toOctet(octet_public, core_generator, false);
    (*out) = (struct ubi_create_key2_out *)calloc(1,sizeof(struct ubi_create_key2_out));
    if((*out) == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).private_key = private_key_out->random_bytes_mod;
    (**out).public_key = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).public_key->buffer = (uint8_t *)(*octet_public).val;
    (**out).public_key->buffer_len = (size_t)(*octet_public).len;
    (**out).generator = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).generator->buffer = (uint8_t *)(*octet_generator).val;
    (**out).generator->buffer_len = (size_t)(*octet_generator).len;
cleanup:
    if(core_generator != NULL){ free(core_generator);}
    if(octet_generator != NULL){ free(octet_generator); }
    if(core_secret != NULL){ free(core_secret); }
    if(octet_public != NULL){ free(octet_public); }
    if(private_key_out != NULL){ free(private_key_out);}
    return ret; 


}

int ubi_create_key2(struct ubi_create_key2_in *in, struct ubi_create_key2_out **out){
    int ret = UBI_SUCCESS;
    switch ((*in).curve_type)
    {
    case BNP_256:
        ret = ubi_create_key_fp256_key2(in, out);
        break;
    
    default:
        ret = UBI_NOT_IMPLEMENTED_ERROR;
        break;
    }
    return ret;
}

int free_ubi_create_key2_out(struct ubi_create_key2_out *out){
    if(out == NULL){
        return UBI_SUCCESS;
    }
    if((*out).private_key != NULL){
        if((*out).private_key->buffer != NULL){
            free((*out).private_key->buffer);
        }
        free((*out).private_key);
    }
    if((*out).public_key != NULL){
        if((*out).public_key->buffer != NULL){
            free((*out).public_key->buffer);
        }
        free((*out).public_key);
    }
    if((*out).generator != NULL){
        if((*out).generator->buffer != NULL){
            free((*out).generator->buffer);
        }
        free((*out).generator);
    }
    free(out);
    return UBI_SUCCESS;
}