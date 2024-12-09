#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>


#include <ubi_crypt/rand.h>
#include <ubi_crypt/numeric.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>


int free_ubi_random_bytes_mod_out(struct ubi_random_bytes_mod_out *out){
    if (out) {
        if ((*out).random_bytes_mod) {
            if ((*out).random_bytes_mod->buffer) {
                free((*out).random_bytes_mod->buffer);
                (*out).random_bytes_mod->buffer = NULL;
            }
            free((*out).random_bytes_mod);
            (*out).random_bytes_mod = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS; 
}

int ubi_random_bytes(void *p_rng, unsigned char *output, size_t bytes_num) 
{
    int ret = UBI_SUCCESS;
    mbedtls_entropy_context *entropy = calloc(1,sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_context *ctr_drbg = calloc(1,sizeof(mbedtls_ctr_drbg_context));
    const char *personalization = "my_random_generator";

    (void)p_rng; 

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    // Seed the CTR_DRBG context
    if ((ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, 
                                     (const unsigned char *)personalization, strlen(personalization))) != 0) 
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }

    // Generate the random bytes
    if ((ret = mbedtls_ctr_drbg_random(ctr_drbg, output, bytes_num)) != 0) 
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }

cleanup:
    // Clean up the contexts
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    free(ctr_drbg);
    free(entropy);
    ctr_drbg = NULL;
    entropy = NULL; 

    return ret;
}

int ubi_random_bytes_mod(struct ubi_random_bytes_mod_in *in, struct ubi_random_bytes_mod_out **out) {
    int ret = UBI_SUCCESS;

    // Validate inputs
    if (!in || !(*in).mod_order || !(*in).mod_order->buffer || !out) {
        return UBI_RAND_ERROR;
    }

    // Generate random bytes
    mbedtls_mpi *rand_mpi = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(rand_mpi);
    mbedtls_mpi *N = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(N);
    mbedtls_mpi_sint min = 0;

    if (((ret = mbedtls_mpi_read_binary(N, (*in).mod_order->buffer, (*in).mod_order->buffer_len)) != 0)) {
        ret = UBI_READ_BIN_ERROR;
        return ret;
    }

    mbedtls_entropy_context *entropy = calloc(1,sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_context *ctr_drbg = calloc(1,sizeof(mbedtls_ctr_drbg_context));
    const char *personalization = "my_random_generator";

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    // Seed the CTR_DRBG context
    if ((ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, 
                                     (const unsigned char *)personalization, strlen(personalization))) != 0) 
    {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_random(rand_mpi, min, N, mbedtls_ctr_drbg_random, ctr_drbg)) != 0) {
        ret = UBI_RAND_ERROR;
        goto cleanup;
    }
    (*out) = (struct ubi_random_bytes_mod_out *)calloc(1,sizeof(struct ubi_random_bytes_mod_out));
    (**out).random_bytes_mod = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).random_bytes_mod ->buffer_len = mbedtls_mpi_size(rand_mpi);
    (**out).random_bytes_mod ->buffer = calloc(1, (**out).random_bytes_mod->buffer_len * sizeof(uint8_t)); 
    if ((ret = mbedtls_mpi_write_binary(rand_mpi, (**out).random_bytes_mod->buffer, (**out).random_bytes_mod->buffer_len)) != 0)
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }

    

cleanup:
    mbedtls_mpi_free(rand_mpi);
    free(rand_mpi);
    rand_mpi = NULL;
    mbedtls_mpi_free(N);  
    free(N);
    N = NULL;
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    free(ctr_drbg);
    ctr_drbg = NULL;
    free(entropy);
    entropy = NULL;

    return ret;
}