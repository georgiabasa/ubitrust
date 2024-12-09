#include <stdlib.h>
#include <stdint.h>

#include <ubi_crypt/hmac.h>
#include <ubi_common/macros.h>
#include <ubi_common/errors.h>
#include <mbedtls/md.h>

void free_ubi_hmac_sha256_out(struct ubi_hmac_sha256_out *out) {
    if (out) {
        if ((*out).hmac_digest) {
            if ((*out).hmac_digest->buffer) {
                free((*out).hmac_digest->buffer);
                (*out).hmac_digest->buffer = NULL;
            }
            free((*out).hmac_digest);
            (*out).hmac_digest = NULL;
        }
        free(out);
        out = NULL;
    }
}

int ubi_hmac_sha256(struct ubi_hmac_sha256_in *in, struct ubi_hmac_sha256_out **out)
{
    int ret = UBI_SUCCESS;
    mbedtls_md_context_t *context = (mbedtls_md_context_t *)calloc(1,sizeof(mbedtls_md_context_t));
    const mbedtls_md_info_t *md_info;
    if (context == NULL) {
        return UBI_MEM_ERROR;
    }
    mbedtls_md_init(context);

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    if (mbedtls_md_setup(context, md_info, 1) != 0) {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }

    if (mbedtls_md_hmac_starts(context, (*in).key->buffer, (*in).key->buffer_len) != 0) {
        ret = UBI_INIT_ERROR;
        goto cleanup;
    }
    for(size_t i = 0; i < (*in).messages_len; i++)
    {
        if (mbedtls_md_hmac_update(context, (*in).messages->buffer, (*in).messages->buffer_len) != 0) {
            ret = UBI_HMAC_ERROR;
            goto cleanup;
        }
    }
    *out = (struct ubi_hmac_sha256_out *)calloc(1,sizeof(struct ubi_hmac_sha256_out));  
    (**out).hmac_digest = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    (**out).hmac_digest->buffer_len = SHA256_DIGEST_LENGTH;
    (**out).hmac_digest->buffer = (uint8_t *)calloc(1,(**out).hmac_digest->buffer_len * sizeof(uint8_t));

    if (mbedtls_md_hmac_finish(context, (**out).hmac_digest->buffer) != 0) {
        ret = UBI_HMAC_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_md_free(context);
    free(context);
    context = NULL;    
    return ret;
}
