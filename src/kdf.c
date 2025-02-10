#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ubi_crypt/kdf.h>
#include <ubi_crypt/hmac.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>


void free_ubi_kdf_out(struct ubi_kdf_out *out) {
    if (out) {
        if ((*out).key) {
            if ((*out).key->buffer) {
                free((*out).key->buffer);
                (*out).key->buffer = NULL;
            }
            free((*out).key);
            (*out).key = NULL;
        }
        free(out);
        out = NULL;
    }
}

int ubi_kdf_sha256(struct ubi_kdf_in *in, struct ubi_kdf_out **out)
{
    int ret = UBI_SUCCESS;
    size_t fixed_data_length = (*in).label->buffer_len + (*in).context_u->buffer_len + (*in).context_v->buffer_len + 4;
    uint8_t *fixed_data = (uint8_t*)calloc(1,fixed_data_length);
    if (fixed_data == NULL)
    {
        return UBI_MEM_ERROR;
    }

    uint8_t size_bin[4];
    size_t i_val = (*in).key_bit_len;
    for (int i = 0; i < 4; ++i)
    {
        size_bin[3 - i] = i_val & 0xff;
        i_val >>= 8;
    }

    memcpy(fixed_data, (*in).label->buffer, (*in).label->buffer_len);
    memcpy(&fixed_data[(*in).label->buffer_len], (*in).context_u->buffer, (*in).context_u->buffer_len);
    memcpy(&fixed_data[(*in).label->buffer_len + (*in).context_u->buffer_len], (*in).context_v->buffer, (*in).context_v->buffer_len);
    memcpy(&fixed_data[(*in).label->buffer_len + (*in).context_u->buffer_len + (*in).context_v->buffer_len], size_bin, 4);

    size_t count = 1;
    size_t n_hashes = (size_t)(*in).key_bit_len / 256;

    uint8_t *input_buffer = (uint8_t *)calloc(1,fixed_data_length + 4);
    if (input_buffer == NULL)
    {
        free(fixed_data);
        fixed_data = NULL;
        return UBI_MEM_ERROR;
    }

    struct ubi_hmac_sha256_out *hmac_out = NULL;  
    for (size_t i = 0; i < n_hashes; i++) 
    {
        uint8_t binary_count[4];
        binary_count[0] = (count >> 24) & 0xFF;
        binary_count[1] = (count >> 16) & 0xFF;
        binary_count[2] = (count >> 8) & 0xFF;
        binary_count[3] = count & 0xFF;

        memcpy(input_buffer, binary_count, 4);
        memcpy(&input_buffer[4], fixed_data, fixed_data_length);

        struct ubi_buffer input_msg = {input_buffer, fixed_data_length + 4};
        struct ubi_hmac_sha256_in hmac_in = {&input_msg, 1, (*in).seed};
        int hmac_status = ubi_hmac_sha256(&hmac_in, &hmac_out);
        if (hmac_status != 0)
        {
            ret = UBI_HMAC_ERROR;
            goto cleanup;  
        }

        count++;
    }
    *out = (struct ubi_kdf_out *)calloc(1,sizeof(struct ubi_kdf_out));
    (**out).key = (*hmac_out).hmac_digest;

cleanup:
    if (fixed_data != NULL) {free(fixed_data); fixed_data = NULL;}
    if (input_buffer != NULL) {free(input_buffer); input_buffer = NULL;}
    if ((*hmac_out).hmac_digest != NULL) {free(hmac_out); hmac_out = NULL;}
    return ret; 
}
