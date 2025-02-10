#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>
#include <ubi_crypt/policy_engine.h>
#include <ubi_crypt/ecdsa.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/hash.h>
#include <string.h>


ubi_policy_session ubi_session_handles[MAX_POLICY_SESSIONS] = {0};

int alloc_ubi_start_policy_session_out(struct ubi_start_policy_session_out **out) {
    *out = (struct ubi_start_policy_session_out*)calloc(1,sizeof(struct ubi_start_policy_session_out));
    if (*out == NULL) {
        return UBI_MEM_ERROR;
    }

    (**out).nonce = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).nonce == NULL) {
        free(*out);
        *out = NULL;
        return UBI_MEM_ERROR;
    }
    (**out).nonce->buffer = (uint8_t*)calloc(1,NONCE_SIZE);
    if ((**out).nonce->buffer == NULL) {
        free((**out).nonce);
        (**out).nonce = NULL;
        free(*out);
        *out = NULL;
        return UBI_MEM_ERROR;
    }
    (**out).nonce->buffer_len = NONCE_SIZE;

    (**out).session_handle = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).session_handle == NULL) {
        free((**out).nonce->buffer);
        (**out).nonce->buffer = NULL;
        free((**out).nonce);
        (**out).nonce = NULL;
        free(*out);
        *out = NULL;
        return UBI_MEM_ERROR;
    }
    (**out).session_handle->buffer = (uint8_t*)calloc(1,SESSION_HANDLE_SIZE);
    if ((**out).session_handle->buffer == NULL) {
        free((**out).session_handle);
        (**out).session_handle = NULL;
        free((**out).nonce->buffer);
        (**out).nonce->buffer = NULL;
        free((**out).nonce);
        (**out).nonce = NULL;
        free(*out);
        *out = NULL;
        return UBI_MEM_ERROR;
    }
    (**out).session_handle->buffer_len = SESSION_HANDLE_SIZE;

    return UBI_SUCCESS;
}

// Free memory allocated for ubi_start_policy_session_out
int free_ubi_start_policy_session_out(struct ubi_start_policy_session_out *out) {
    if (out) {
        if ((*out).nonce) {
            if ((*out).nonce->buffer) {free((*out).nonce->buffer); (*out).nonce->buffer = NULL;}
            free((*out).nonce);
            (*out).nonce = NULL;
        }
        if ((*out).session_handle) {
            if ((*out).session_handle->buffer) {free((*out).session_handle->buffer); (*out).session_handle->buffer = NULL;}
            free((*out).session_handle);
            (*out).session_handle = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}

// The function being tested
int ubi_start_policy_session(void *in, struct ubi_start_policy_session_out **out) {
    int ret = UBI_SUCCESS;
    uint8_t zero_handle[SESSION_HANDLE_SIZE] = {0}; // Array of zeros for comparison

    for (int i = 0; i < MAX_POLICY_SESSIONS; i++) {
        if (memcmp(ubi_session_handles[i].session_handle, zero_handle, SESSION_HANDLE_SIZE) == 0) {
            // Generate random session handle and nonce
            if (ubi_random_bytes(NULL, ubi_session_handles[i].session_handle, SESSION_HANDLE_SIZE) != 0 ||
                ubi_random_bytes(NULL, ubi_session_handles[i].nonce, NONCE_SIZE) != 0) 
            {
                ret = UBI_RAND_ERROR;
                goto cleanup;
            }

            // Allocate memory for output
            if ((ret = alloc_ubi_start_policy_session_out(out)) != UBI_SUCCESS) {
                goto cleanup;
            }

            // Copy data to output
            memcpy((**out).nonce->buffer, ubi_session_handles[i].nonce, NONCE_SIZE);
            memcpy((**out).session_handle->buffer, ubi_session_handles[i].session_handle, SESSION_HANDLE_SIZE);

            goto cleanup;
        }
    }

    // If no session is available, return error
    ret = UBI_POLICY_START_ERROR;

cleanup:
    return ret;
}

/**
 * Verifies a signed policy using ECDSA and updates the session digest.
 * 
 * @param in  Input structure containing the signed policy and related data.
 * @param out Output parameter (currently unused).
 * @return    UBI_SUCCESS on success, or an appropriate error code on failure.
 */
int ubi_policy_signed(struct ubi_policy_signed_in *in, void *out) {
    int ret = UBI_SUCCESS;

    for (int i = 0; i < MAX_POLICY_SESSIONS; i++) {
        if (memcmp(ubi_session_handles[i].session_handle, (*in).session_handle->buffer, (*in).session_handle->buffer_len) == 0) {
            


            ubi_sha_in sha_in;
            sha_in.messages = (struct ubi_buffer **)calloc(3, sizeof(struct ubi_buffer *));
            sha_in.messages[0] = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
            sha_in.messages[0]->buffer_len = CC_LENGTH;
            sha_in.messages[0]->buffer = (uint8_t *)POLICY_SIGNED_CC;
            sha_in.messages[1] = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
            sha_in.messages[1]->buffer_len = NONCE_SIZE;
            sha_in.messages[1]->buffer = (uint8_t *)ubi_session_handles[i].nonce;
            sha_in.messages[2] = (*in).digest;
            sha_in.messages_len = 3;
            ubi_sha_out *sha_out = NULL;


            ret = ubi_sha256(&sha_in, &sha_out);
            if (ret != UBI_SUCCESS) {
                free(sha_in.messages[0]);
                free(sha_in.messages[1]);
                free(sha_in.messages);
                goto cleanup;
            }


            ubi_ecdsa_verify_in *verify_in = (struct ubi_ecdsa_verify_in *)calloc(1,sizeof(struct ubi_ecdsa_verify_in));
            if (!verify_in) {
                ret = UBI_MEM_ERROR;
                free(sha_in.messages[0]);
                free(sha_in.messages[1]);
                free(sha_in.messages);
                goto cleanup;
            }

            (*verify_in).curve_type = (*in).curve_type;
            (*verify_in).digest = (*sha_out).digest;  
            (*verify_in).signature_r = (*in).signature_r;
            (*verify_in).signature_s = (*in).signature_s;
            (*verify_in).public_key = (*in).public_key;
            

            ubi_ecdsa_verify_out verify_out = {0};
            ret = ubi_ecdsa_verify(verify_in, &verify_out);
            if (ret != UBI_SUCCESS) {
                ret = UBI_VERIFY_ERROR;
                free(sha_in.messages[0]);
                free(sha_in.messages[1]);
                free(sha_in.messages);
                free((*sha_out).digest->buffer);
                (*sha_out).digest->buffer = NULL;
                free((*sha_out).digest);
                (*sha_out).digest = NULL;
                free(sha_out);  
                sha_out = NULL;
                free(verify_in);
                verify_in = NULL;
                goto cleanup;
            }

            // Calculate the hash of the concatenation of POLICY_SIGNED_CC and public_key
            ubi_sha_in concat_sha_in;
            concat_sha_in.messages = (struct ubi_buffer **)calloc(2, sizeof(struct ubi_buffer *));
            concat_sha_in.messages[0] = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
            concat_sha_in.messages[0]->buffer_len = CC_LENGTH;
            concat_sha_in.messages[0]->buffer = (uint8_t *)POLICY_SIGNED_CC;
            concat_sha_in.messages[1] = (*in).public_key;
            concat_sha_in.messages_len = 2;
            ubi_sha_out *concat_sha_out = NULL;

            ret = ubi_sha256(&concat_sha_in, &concat_sha_out);
            if (ret == UBI_SUCCESS) {
                memcpy(ubi_session_handles[i].session_digest, (*concat_sha_out).digest->buffer, SHA256_DIGEST_LENGTH);
            }

            // Clean up dynamically allocated memory
            free(sha_in.messages[0]);
            free(sha_in.messages[1]);
            free(sha_in.messages);
            free((*sha_out).digest->buffer);
            (*sha_out).digest->buffer = NULL;   
            free((*sha_out).digest);
            (*sha_out).digest = NULL;
            free(sha_out);  
            sha_out = NULL;
            free(verify_in);
            verify_in = NULL;
            free((*concat_sha_out).digest->buffer);
            (*concat_sha_out).digest->buffer = NULL;
            free((*concat_sha_out).digest);
            (*concat_sha_out).digest = NULL;
            free(concat_sha_out);   
            free(concat_sha_in.messages[0]);
            free(concat_sha_in.messages);

            concat_sha_out = NULL;
            return ret;
        }
    }

    ret = UBI_POLICY_SIGNED_ERROR;

cleanup:
    return ret;
}


int ubi_get_policy_digest(ubi_buffer *in, ubi_buffer **out) {
    for (int i = 0; i < MAX_POLICY_SESSIONS; i++) {
        if (memcmp(ubi_session_handles[i].session_handle, (*in).buffer, (*in).buffer_len) == 0) {
            *out = (ubi_buffer *)calloc(1,sizeof(ubi_buffer));
            if (*out == NULL) {
                return UBI_MEM_ERROR;
            }
            (**out).buffer = (uint8_t *)calloc(1,SHA256_DIGEST_LENGTH);
            memcpy((**out).buffer, ubi_session_handles[i].session_digest, SHA256_DIGEST_LENGTH);
            (**out).buffer_len = SHA256_DIGEST_LENGTH;
            
            return UBI_SUCCESS;
        }
    }
    return UBI_INVALID_POLICY_HANDLE;
}   