#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/ecdsa.h>
#include <ubi_crypt/ec.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/ecdsa.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>


void free_ubi_ecdsa_sign_out(struct ubi_ecdsa_sign_out *sign_out) {
    if (sign_out) {
        if ((*sign_out).signature_r) {
            if ((*sign_out).signature_r->buffer) {
                free((*sign_out).signature_r->buffer);
                (*sign_out).signature_r->buffer = NULL;
            }
            free((*sign_out).signature_r);
            (*sign_out).signature_r = NULL;
        }
        if ((*sign_out).signature_s) {
            if ((*sign_out).signature_s->buffer) {
                free((*sign_out).signature_s->buffer);
                (*sign_out).signature_s->buffer = NULL;
            }
            free((*sign_out).signature_s);
            (*sign_out).signature_s = NULL;
        }
        free(sign_out);
        sign_out = NULL;
    }
}

int ubi_ecdsa_sign(struct ubi_ecdsa_sign_in *in, struct ubi_ecdsa_sign_out **out)
{
    int ret = UBI_SUCCESS; // Default to error
    mbedtls_mpi *r = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *s = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *d = (mbedtls_mpi*)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_ecp_group *grp = NULL;

    mbedtls_mpi_init(r); 
    mbedtls_mpi_init(s); 
    mbedtls_mpi_init(d); 
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
    if ((ret = mbedtls_mpi_read_binary(d, (*in).private_key->buffer, (*in).private_key->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }


    if ((ret = mbedtls_ecdsa_sign(grp, r, s, d, (*in).digest->buffer, (*in).digest->buffer_len, ubi_random_bytes, NULL)) != 0)
    {
        ret = UBI_SIGN_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_ecdsa_sign_out *)calloc(1,sizeof(struct ubi_ecdsa_sign_out));
    (**out).signature_r = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).signature_r->buffer_len = mbedtls_mpi_size(r);
    (**out).signature_r->buffer = calloc((**out).signature_r->buffer_len,sizeof(uint8_t));
    if ((ret = mbedtls_mpi_write_binary(r, (**out).signature_r->buffer, (**out).signature_r->buffer_len)) != 0)
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
    (**out).signature_s = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).signature_s->buffer_len = mbedtls_mpi_size(s);
    (**out).signature_s->buffer = calloc((**out).signature_s->buffer_len, sizeof(uint8_t));
    if ((ret = mbedtls_mpi_write_binary(s, (**out).signature_s->buffer, (**out).signature_s->buffer_len)) != 0)
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }


cleanup:
    mbedtls_mpi_free(r); 
    mbedtls_mpi_free(s); 
    mbedtls_mpi_free(d);
    free_ubi_ecp_group(grp);
    free(grp);
    free(r);
    free(s);
    free(d);
    grp = NULL;
    r = NULL;
    s = NULL;
    d = NULL;
    return ret;
}

int ubi_ecdsa_verify(struct ubi_ecdsa_verify_in *in, struct ubi_ecdsa_verify_out *out)
{
    int ret = UBI_SUCCESS;
    mbedtls_ecp_point *Q = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_mpi *r = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *s = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    
    mbedtls_ecp_point_init(Q);
    mbedtls_mpi_init(r);
    mbedtls_mpi_init(s);

    mbedtls_ecp_group *grp = NULL;
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
        goto cleanup;
    }
    if ((ret = mbedtls_ecp_point_read_binary(grp, Q, (*in).public_key->buffer, (*in).public_key->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(r, (*in).signature_r->buffer, (*in).signature_r->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(s, (*in).signature_s->buffer, (*in).signature_s->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if (((*out).verification_status = (size_t)mbedtls_ecdsa_verify(grp, (*in).digest->buffer, (*in).digest->buffer_len, Q, r, s)) != 0) 
    {
        ret = UBI_VERIFY_ERROR;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(Q);
    mbedtls_mpi_free(r);
    mbedtls_mpi_free(s);
    free_ubi_ecp_group(grp);
    free(Q);
    free(r);
    free(s);
    free(grp);
    Q = NULL;
    r = NULL;
    s = NULL;
    grp = NULL;

    return ret;
}
