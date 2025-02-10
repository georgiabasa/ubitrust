#include <stdlib.h>
#include <stdint.h>
#include <mbedtls/bignum.h>
#include <ubi_crypt/numeric.h>
#include <ubi_common/errors.h>

int free_ubi_mod_out(struct ubi_mod_out *out) 
{
    if (out) 
    {
        if ((*out).output) 
        {
            if ((*out).output->buffer) 
            {
                free((*out).output->buffer);
                (*out).output->buffer = NULL;
            }
            free((*out).output);
            (*out).output = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}

int ubi_mod(struct ubi_mod_in *in, struct ubi_mod_out **out) 
{
    int ret = UBI_SUCCESS;
    mbedtls_mpi mod_mpi;
    mbedtls_mpi num_mpi;
    mbedtls_mpi res_mpi;

    mbedtls_mpi_init(&mod_mpi);
    mbedtls_mpi_init(&num_mpi);
    mbedtls_mpi_init(&res_mpi);

    if ((ret = mbedtls_mpi_read_binary(&mod_mpi, (*in).mod->buffer, (*in).mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(&num_mpi, (*in).input->buffer, (*in).input->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_mod_mpi(&res_mpi, &num_mpi, &mod_mpi)) != 0) 
    {
        ret = UBI_MOD_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_mod_out *)calloc(1,sizeof(struct ubi_mod_out));
    (**out).output = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).output->buffer_len = mbedtls_mpi_size(&res_mpi);
    (**out).output->buffer = (uint8_t *)calloc(1,(**out).output->buffer_len);
    if (!(**out).output->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_write_binary(&res_mpi, (**out).output->buffer, (**out).output->buffer_len)) != 0) 
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&mod_mpi);
    mbedtls_mpi_free(&num_mpi);
    mbedtls_mpi_free(&res_mpi);
    if(ret != UBI_SUCCESS){ free_ubi_mod_out(*out);}

    return ret;
}

int ubi_mod_add(struct ubi_mod_add_in *in, struct ubi_mod_add_out **out){
    int ret = UBI_SUCCESS;
    mbedtls_mpi *mod_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *adder_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *res_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    if(!mod_mpi || !adder_mpi || !res_mpi){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_mpi_init(mod_mpi);
    mbedtls_mpi_init(adder_mpi);
    mbedtls_mpi_init(res_mpi);
    mbedtls_mpi_lset(res_mpi, 0);

    if ((ret = mbedtls_mpi_read_binary(mod_mpi, (*in).mod->buffer, (*in).mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    for(size_t i=0; i<(*in).adder_num; i++){
        if ((ret = mbedtls_mpi_read_binary(adder_mpi, (*in).adder[i]->buffer, (*in).adder[i]->buffer_len)) != 0) 
        {
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_mpi_add_mpi(res_mpi, res_mpi, adder_mpi)) != 0) 
        {
            ret = UBI_ADD_MOD_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_mpi_mod_mpi(res_mpi, res_mpi, mod_mpi)) != 0) 
        {
            ret = UBI_MOD_ERROR;
            goto cleanup;
        }
    }
    *out = (struct ubi_mod_add_out *)calloc(1,sizeof(struct ubi_mod_add_out));
    (**out).output = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).output->buffer_len = mbedtls_mpi_size(res_mpi);
    (**out).output->buffer = (uint8_t *)calloc(1,(**out).output->buffer_len);
    if (!(**out).output->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_mpi_write_binary(res_mpi, (**out).output->buffer, (**out).output->buffer_len)) != 0){
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free(mod_mpi); free(mod_mpi); mod_mpi = NULL;
    mbedtls_mpi_free(adder_mpi); free(adder_mpi); adder_mpi = NULL; 
    mbedtls_mpi_free(res_mpi); free(res_mpi); res_mpi = NULL;   
    return ret;
}

int free_ubi_mod_add_out(struct ubi_mod_add_out *out) 
{
    if (out) 
    {
        if ((*out).output) 
        {
            if ((*out).output->buffer) 
            {
                free((*out).output->buffer);
                (*out).output->buffer = NULL;
            }
            free((*out).output);
            (*out).output = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}

int ubi_mod_mul(struct ubi_mod_mul_in *in, struct ubi_mod_mul_out **out){
    int ret = UBI_SUCCESS;
    mbedtls_mpi *mod_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *mult_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *res_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    if(!mod_mpi || !mult_mpi || !res_mpi){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_mpi_init(mod_mpi);
    mbedtls_mpi_init(mult_mpi);
    mbedtls_mpi_init(res_mpi);
    mbedtls_mpi_lset(res_mpi, 1);

    if ((ret = mbedtls_mpi_read_binary(mod_mpi, (*in).mod->buffer, (*in).mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    for(size_t i=0; i<(*in).mult_num; i++){
        if ((ret = mbedtls_mpi_read_binary(mult_mpi, (*in).mult[i]->buffer, (*in).mult[i]->buffer_len)) != 0) 
        {
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_mpi_mul_mpi(res_mpi, res_mpi, mult_mpi)) != 0) 
        {
            ret = UBI_MULL_MOD_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_mpi_mod_mpi(res_mpi, res_mpi, mod_mpi)) != 0) 
        {
            ret = UBI_MOD_ERROR;
            goto cleanup;
        }
    }
    *out = (struct ubi_mod_mul_out *)calloc(1,sizeof(struct ubi_mod_mul_out));
    (**out).output = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).output->buffer_len = mbedtls_mpi_size(res_mpi);
    (**out).output->buffer = (uint8_t *)calloc(1,(**out).output->buffer_len);
    if (!(**out).output->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_mpi_write_binary(res_mpi, (**out).output->buffer, (**out).output->buffer_len)) != 0){
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free(mod_mpi); free(mod_mpi); mod_mpi = NULL;
    mbedtls_mpi_free(mult_mpi); free(mult_mpi); mult_mpi = NULL; 
    mbedtls_mpi_free(res_mpi); free(res_mpi); res_mpi = NULL;   
    return ret;
}

int free_ubi_mod_mul_out(struct ubi_mod_mul_out *out) 
{
    if (out) 
    {
        if ((*out).output) 
        {
            if ((*out).output->buffer) 
            {
                free((*out).output->buffer);
                (*out).output->buffer = NULL;
            }
            free((*out).output);
            (*out).output = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}   


int ubi_mod_inverse(struct ubi_mod_inv_in *in, struct ubi_mod_inv_out **out) 
{
    int ret = UBI_SUCCESS;
    mbedtls_mpi *mod_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *num_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *res_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));

    if(!mod_mpi || !num_mpi || !res_mpi){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_mpi_init(mod_mpi);
    mbedtls_mpi_init(num_mpi);
    mbedtls_mpi_init(res_mpi);

    if ((ret = mbedtls_mpi_read_binary(mod_mpi, (*in).mod->buffer, (*in).mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(num_mpi, (*in).input->buffer, (*in).input->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_inv_mod(res_mpi, num_mpi, mod_mpi)) != 0) 
    {
        ret = UBI_MOD_INV_ERROR;
        goto cleanup;
    }
    *out = (struct ubi_mod_inv_out *)calloc(1,sizeof(struct ubi_mod_inv_out));
    (**out).output = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).output->buffer_len = mbedtls_mpi_size(res_mpi);
    (**out).output->buffer = (uint8_t *)calloc(1,(**out).output->buffer_len);
    if (!(**out).output->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_write_binary(res_mpi, (**out).output->buffer, (**out).output->buffer_len)) != 0) 
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free(mod_mpi); free(mod_mpi); mod_mpi = NULL;
    mbedtls_mpi_free(num_mpi); free(num_mpi); num_mpi = NULL;
    mbedtls_mpi_free(res_mpi); free(res_mpi); res_mpi = NULL;

    return ret;
}

int free_ubi_mod_inv_out(struct ubi_mod_inv_out *out) 
{
    if (out) 
    {
        if ((*out).output) 
        {
            if ((*out).output->buffer) 
            {
                free((*out).output->buffer);
                (*out).output->buffer = NULL;
            }
            free((*out).output);
            (*out).output = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}



int ubi_mod_sub(struct ubi_mod_sub_in *in, struct ubi_mod_sub_out **out){
    int ret = UBI_SUCCESS;
    mbedtls_mpi *mod_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *sub_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi *res_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    if(!mod_mpi || !sub_mpi || !res_mpi){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    mbedtls_mpi_init(mod_mpi);
    mbedtls_mpi_init(sub_mpi);
    mbedtls_mpi_init(res_mpi);
    mbedtls_mpi_lset(res_mpi, 0);

    if ((ret = mbedtls_mpi_read_binary(mod_mpi, (*in).mod->buffer, (*in).mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(res_mpi, (*in).src->buffer, (*in).src->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(sub_mpi, (*in).sub->buffer, (*in).sub->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_mpi_sub_mpi(res_mpi, res_mpi, sub_mpi)) != 0) 
    {
        ret = UBI_SUB_MOD_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_mpi_mod_mpi(res_mpi, res_mpi, mod_mpi)) != 0) 
    {
        ret = UBI_MOD_ERROR;
        goto cleanup;
    }
    
    *out = (struct ubi_mod_sub_out *)calloc(1,sizeof(struct ubi_mod_add_out));
    (**out).output = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).output->buffer_len = mbedtls_mpi_size(res_mpi);
    (**out).output->buffer = (uint8_t *)calloc(1,(**out).output->buffer_len);
    if (!(**out).output->buffer) 
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_mpi_write_binary(res_mpi, (**out).output->buffer, (**out).output->buffer_len)) != 0){
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free(mod_mpi); free(mod_mpi); mod_mpi = NULL;
    mbedtls_mpi_free(sub_mpi); free(sub_mpi); sub_mpi = NULL; 
    mbedtls_mpi_free(res_mpi); free(res_mpi); res_mpi = NULL;   
    return ret;
}

int free_ubi_mod_sub_out(struct ubi_mod_sub_out *out) 
{
    if (out) 
    {
        if ((*out).output) 
        {
            if ((*out).output->buffer) 
            {
                free((*out).output->buffer);
                (*out).output->buffer = NULL;
            }
            free((*out).output);
            (*out).output = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}   