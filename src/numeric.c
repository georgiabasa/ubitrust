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
