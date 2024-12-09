#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/sha256.h>
#include <ubi_crypt/hash.h>
#include <ubi_common/macros.h>
#include <ubi_common/errors.h>


void free_ubi_sha_out(struct ubi_sha_out *out) {
    if (out) {
        if ((*out).digest) {
            if ((*out).digest->buffer) {
                free((*out).digest->buffer);
                (*out).digest->buffer = NULL;
            }
            free((*out).digest);
            (*out).digest = NULL;
        }
        free(out);
        out = NULL;
    }
}

int ubi_sha256(struct ubi_sha_in *in, struct ubi_sha_out **out) {
    int ret = UBI_SUCCESS;
    mbedtls_sha256_context *context = calloc(1,sizeof(mbedtls_sha256_context));
    if (context == NULL) {
        return UBI_MEM_ERROR;
    }

    mbedtls_sha256_init(context);

    if (mbedtls_sha256_starts(context, 0) != 0) {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    for (size_t i = 0; i < (*in).messages_len; i++) {
        if (mbedtls_sha256_update(context, (*in).messages[i].buffer, (*in).messages[i].buffer_len) != 0) {
            ret = UBI_SHA256_ERROR;
            goto cleanup;
        }
    }
    *out = (struct ubi_sha_out *)calloc(1,sizeof(struct ubi_sha_out));
    
    (**out).digest = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).digest->buffer = (uint8_t *)calloc(1,SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    if ((**out).digest == NULL || (**out).digest->buffer == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    if (mbedtls_sha256_finish(context, (**out).digest->buffer) != 0) {
        ret = UBI_SHA256_ERROR;
        goto cleanup;
    }

    (**out).digest->buffer_len = SHA256_DIGEST_LENGTH;

    

cleanup:
    mbedtls_sha256_free(context);
    free(context);
    context = NULL;
    return ret;
}
