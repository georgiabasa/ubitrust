#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/sha256.h>


#include <ubi_crypt/ec.h>
#include <ubi_crypt/rand.h> 
#include <ubi_crypt/schnorr.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>


int ubi_schnorr_sign(struct ubi_schnorr_sign_in *in, struct ubi_schnorr_sign_out **out){
    int ret = UBI_SUCCESS;
    mbedtls_ecp_group *grp = NULL;
    mbedtls_ecp_point *R_ecp = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_sha256_context *context = calloc(1,sizeof(mbedtls_sha256_context));
    uint8_t e[SHA256_DIGEST_LENGTH];
    mbedtls_entropy_context *entropy = calloc(1,sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_context *ctr_drbg = calloc(1,sizeof(mbedtls_ctr_drbg_context));
    const char *personalization = "my_random_generator";
    mbedtls_mpi *k_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *sigma_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *x_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *e_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(k_mpi);
    mbedtls_mpi_init(sigma_mpi);
    mbedtls_mpi_init(x_mpi);
    mbedtls_mpi_init(e_mpi);
    mbedtls_mpi_sint min = 0;
    mbedtls_ecp_point_init(R_ecp);
    
    switch ((*in).curve_type) {
        case BNP_256:
            ubi_get_ec_group_bnp256(&grp);
            break;
        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }

    
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, 
                                     (const unsigned char *)personalization, strlen(personalization))) != UBI_SUCCESS) 
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_random(k_mpi, min, &(*grp).N, mbedtls_ctr_drbg_random, ctr_drbg)) != UBI_SUCCESS) {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_ecp_mul(grp, R_ecp, k_mpi, &(*grp).G, ubi_random_bytes, NULL)) != UBI_SUCCESS)
    {
        ret = UBI_ECP_MUL_ERROR;
        goto cleanup;
    }
    mbedtls_sha256_init(context);

    if (mbedtls_sha256_starts(context, 0) != 0) {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_schnorr_sign_out *)calloc(1,sizeof(struct ubi_schnorr_sign_out));
    (**out).signature_r = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    ubi_get_ecp_size(grp, &(**out).signature_r->buffer_len);
    (**out).signature_r->buffer = (uint8_t *)calloc((**out).signature_r->buffer_len, sizeof(uint8_t));
    if ((ret = mbedtls_ecp_point_write_binary(grp, R_ecp, MBEDTLS_ECP_PF_UNCOMPRESSED, &(**out).signature_r->buffer_len, (**out).signature_r->buffer, (**out).signature_r->buffer_len)) != 0) {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
    if (mbedtls_sha256_update(context, (**out).signature_r->buffer, (**out).signature_r->buffer_len) != 0) {
        ret = UBI_SHA256_ERROR;
        goto cleanup;
    }
    if (mbedtls_sha256_update(context, (*in).digest->buffer, (*in).digest->buffer_len) != 0) {
        ret = UBI_SHA256_ERROR;
        goto cleanup;
    }
    if (mbedtls_sha256_finish(context, e) != 0) {
        ret = UBI_SHA256_ERROR;
        goto cleanup;
    }
    mbedtls_mpi_read_binary(e_mpi, e, SHA256_DIGEST_LENGTH);
    mbedtls_mpi_read_binary(x_mpi, (*in).private_key->buffer, (*in).private_key->buffer_len);
    if ((ret = mbedtls_mpi_mul_mpi(sigma_mpi, e_mpi, x_mpi)) != 0) 
    {
        ret = UBI_MULL_MOD_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_mpi_add_mpi(sigma_mpi, k_mpi, sigma_mpi)) != 0) 
    {
        ret = UBI_ADD_MOD_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_mpi_mod_mpi(sigma_mpi, sigma_mpi, &grp->N)) != 0) 
    {
        ret = UBI_MOD_ERROR;
        goto cleanup;
    }
    (**out).signature_s = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).signature_s->buffer_len = mbedtls_mpi_size(sigma_mpi);
    (**out).signature_s->buffer = (uint8_t *)calloc((**out).signature_s->buffer_len, sizeof(uint8_t));
    if ((ret = mbedtls_mpi_write_binary(sigma_mpi, (**out).signature_s->buffer, (**out).signature_s->buffer_len)) != 0) {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }


cleanup:
    free_ubi_ecp_group(grp);
    free(grp);
    grp = NULL;
    mbedtls_ecp_point_free(R_ecp);
    free(R_ecp);
    R_ecp = NULL;
    mbedtls_mpi_free(k_mpi);
    free(k_mpi);
    k_mpi = NULL;
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    free(ctr_drbg);
    free(entropy);
    ctr_drbg = NULL;
    entropy = NULL;
    mbedtls_mpi_free(sigma_mpi);
    free(sigma_mpi);
    sigma_mpi = NULL;
    mbedtls_mpi_free(x_mpi);
    free(x_mpi);
    x_mpi = NULL;
    mbedtls_mpi_free(e_mpi);
    free(e_mpi);
    e_mpi = NULL;
    mbedtls_sha256_free(context);
    free(context);
    context = NULL;


    return ret;
}

int free_ubi_schnorr_signature_out(struct ubi_schnorr_sign_out *out) 
{
    if (out) 
    {
        if ((*out).signature_r) 
        {
            if ((*out).signature_r->buffer) 
            {
                free((*out).signature_r->buffer);
                (*out).signature_r->buffer = NULL;
            }
            free((*out).signature_r);
            (*out).signature_r = NULL;
        }
        if ((*out).signature_s) 
        {
            if ((*out).signature_s->buffer) 
            {
                free((*out).signature_s->buffer);
                (*out).signature_s->buffer = NULL;
            }
            free((*out).signature_s);
            (*out).signature_s = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}


int ubi_schnorr_verify(struct ubi_schnorr_verify_in *in, struct ubi_schnorr_verify_out *out){
    int ret = UBI_SUCCESS;
    mbedtls_ecp_group *grp = NULL;
    mbedtls_sha256_context *context = calloc(1,sizeof(mbedtls_sha256_context));
    uint8_t e[SHA256_DIGEST_LENGTH];
    mbedtls_mpi *e_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *e_minus_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *s_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *n = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_ecp_point *R_prime_ecp = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point *y_e = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point *g_s = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    uint8_t *R_prime = NULL;
    size_t olen;

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
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    mbedtls_sha256_init(context);
    mbedtls_sha256_starts(context, 0);
    mbedtls_sha256_update(context, (*in).signature_r->buffer, (*in).signature_r->buffer_len);
    mbedtls_sha256_update(context, (*in).digest->buffer, (*in).digest->buffer_len);
    mbedtls_sha256_finish(context, e);

    mbedtls_mpi_init(e_mpi);
    mbedtls_mpi_read_binary(e_mpi, e, SHA256_DIGEST_LENGTH);
    mbedtls_mpi_init(n);
    if(mbedtls_mpi_lset(n, -1) != UBI_SUCCESS){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    mbedtls_mpi_init(e_minus_mpi);
    if ((ret = mbedtls_mpi_mul_mpi(e_minus_mpi, e_mpi, n)) != UBI_SUCCESS) 
    {
        ret = UBI_MULL_MOD_ERROR;
        goto cleanup;
    }
    mbedtls_mpi_mod_mpi(e_minus_mpi, e_minus_mpi, &grp->N);

    mbedtls_ecp_point_init(y_e);
    if ((ret = mbedtls_ecp_point_read_binary(grp, y_e, (*in).public_key->buffer, (*in).public_key->buffer_len)) != UBI_SUCCESS) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_ecp_mul(grp, y_e, e_minus_mpi, y_e, ubi_random_bytes, NULL)) != UBI_SUCCESS)
    {
        ret = UBI_ECP_MUL_ERROR;
        goto cleanup;
    }
    mbedtls_ecp_point_init(g_s);
    mbedtls_mpi_init(s_mpi);
    mbedtls_mpi_read_binary(s_mpi, (*in).signature_s->buffer, (*in).signature_s->buffer_len);
    if ((ret = mbedtls_ecp_mul(grp, g_s, s_mpi, &(*grp).G, ubi_random_bytes, NULL)) != UBI_SUCCESS)
    {
        ret = UBI_ECP_MUL_ERROR;
        goto cleanup;
    }
    if(mbedtls_mpi_lset(n, 1) != UBI_SUCCESS){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    mbedtls_ecp_point_init(R_prime_ecp); 
    if ((ret = mbedtls_ecp_muladd(grp, R_prime_ecp, n, g_s, n, y_e)) != UBI_SUCCESS)
    {
        ret = UBI_ECP_ADD_ERROR;
        goto cleanup;
    }
    ubi_get_ecp_size(grp, &olen);
    R_prime = (uint8_t *)calloc(olen, sizeof(uint8_t));
    if ((ret = mbedtls_ecp_point_write_binary(grp, R_prime_ecp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, R_prime, olen)) != 0) {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }

    if (memcmp(R_prime, (*in).signature_r->buffer, (*in).signature_r->buffer_len) != 0) {
        ret = UBI_VERIFY_ERROR;
        goto cleanup;
    }
    (*out).verification_status = UBI_SUCCESS;





cleanup:
    free_ubi_ecp_group(grp);
    free(grp);
    grp = NULL;
    mbedtls_mpi_free(e_mpi);
    free(e_mpi);
    e_mpi = NULL;
    mbedtls_mpi_free(e_minus_mpi);
    free(e_minus_mpi);
    e_minus_mpi = NULL;
    mbedtls_mpi_free(s_mpi);
    free(s_mpi);
    s_mpi = NULL;
    mbedtls_mpi_free(n);
    free(n);
    n = NULL;
    mbedtls_ecp_point_free(R_prime_ecp);
    free(R_prime_ecp);
    R_prime_ecp = NULL;
    mbedtls_ecp_point_free(y_e);
    free(y_e);
    y_e = NULL;
    mbedtls_ecp_point_free(g_s);
    free(g_s);
    g_s = NULL;
    free(R_prime);
    R_prime = NULL;
    mbedtls_sha256_free(context);
    free(context);
    context = NULL;

    return ret;
}