#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>
#include <ubi_crypt/hash.h>
#include <ubi_crypt/policy_engine.h>
#include <ubi_crypt/ecdsa.h>


// Provided private key (32 bytes)
uint8_t private_key_bytes[32] = {
    0x81, 0x02, 0xa8, 0xd7, 0x6c, 0xba, 0x94, 0xe1,
    0x4f, 0xa6, 0x47, 0xc7, 0xe9, 0x49, 0x19, 0x20,
    0x48, 0x2d, 0xfb, 0xf9, 0xbe, 0x04, 0x0d, 0xb7,
    0x27, 0xe6, 0x7c, 0x8e, 0x1d, 0xa1, 0xfa, 0xb2
};

// Provided public key (uncompressed, 65 bytes)
uint8_t public_key_bytes[65] = {
    0x04, 0x32, 0x49, 0x18, 0xbe, 0x29, 0xfd, 0x70,
    0x90, 0x28, 0x30, 0xc3, 0x5a, 0x4d, 0x5f, 0xf3,
    0x71, 0xd4, 0x39, 0xef, 0x23, 0xc3, 0x7f, 0xde,
    0xde, 0x1a, 0xca, 0xc9, 0xc5, 0x1e, 0x78, 0x1c,
    0xfd, 0xb2, 0xc0, 0x35, 0x85, 0xc2, 0xaa, 0x3f,
    0x0f, 0x75, 0xdb, 0x95, 0x31, 0xd1, 0xec, 0xf5,
    0xab, 0x1d, 0x0d, 0xe1, 0x21, 0x53, 0xdb, 0x6d,
    0x2f, 0x67, 0xee, 0x6e, 0xd1, 0x29, 0xa7, 0x18, 
    0x20
};

// Message digest (32 bytes, SHA-256 digest)
uint8_t digest_bytes[32] = {
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    0x0e, 0xe3, 0x90, 0xf3, 0x55, 0x73, 0x50, 0x05,
    0x23, 0x32, 0x13, 0x19, 0x00, 0x92, 0x4a, 0xb6
};

int main(void) {
    // Prepare output structure
    struct ubi_start_policy_session_out *out = NULL;

    // Call the function
    int result = ubi_start_policy_session(NULL, &out);

    // Check the result and print output
    if (result == UBI_SUCCESS) {
        printf("Nonce: ");
        for (size_t i = 0; i < (*out).nonce->buffer_len; i++) {
            printf("%02x", (*out).nonce->buffer[i]);
        }
        printf("\nSession Handle: ");
        for (size_t i = 0; i < (*out).session_handle->buffer_len; i++) {
            printf("%02x", (*out).session_handle->buffer[i]);
        }
        printf("\nTest Passed\n");
    } else if (result == UBI_RAND_ERROR) {
        printf("Random byte generation failed.\nTest Failed\n");
    } else if (result == UBI_POLICY_START_ERROR) {
        printf("Policy session start failed.\nTest Failed\n");
    }
    ubi_buffer **messages = (struct ubi_buffer **)calloc(3, sizeof(struct ubi_buffer *));
    for (int i = 0; i < 3; i++) {
        messages[i] = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
    }
    messages[0]->buffer_len = CC_LENGTH;
    messages[0]->buffer = (uint8_t *)POLICY_SIGNED_CC;
    messages[1]->buffer_len = NONCE_SIZE;
    messages[1]->buffer = (uint8_t *)(*out).nonce->buffer;
    messages[2]->buffer_len = SHA256_DIGEST_LENGTH;
    messages[2]->buffer = (uint8_t *)digest_bytes;
    ubi_sha_in  sha_in = {
        .messages = messages,
        .messages_len = 3
    };
    
    ubi_sha_out *sha_out = NULL;
    result = ubi_sha256(&sha_in, &sha_out);
    if (result == 0) {
        printf("SHA256 Digest: ");
        for (size_t i = 0; i < (*sha_out).digest->buffer_len; i++) {
            printf("%02x", (*sha_out).digest->buffer[i]);
        }
        printf("\nTest Passed\n");
    } else {
        printf("Test Failed\n");
    }
    ubi_ecdsa_sign_in sign_in;
    ubi_ecdsa_sign_out *sign_out = NULL;
    struct ubi_buffer private_key = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };
    struct ubi_buffer digest = { .buffer = (*sha_out).digest->buffer, .buffer_len = sizeof(digest_bytes) };

    sign_in.private_key = &private_key;
    sign_in.digest = &digest;
    sign_in.curve_type = BNP_256;

    result = ubi_ecdsa_sign(&sign_in, &sign_out);
    if (result != UBI_SUCCESS) {
        printf("Failed to sign the message. Error code: %d\n", result);
        return result;
    }
    ubi_buffer public_key = { .buffer = public_key_bytes, .buffer_len = sizeof(public_key_bytes) };

    struct ubi_policy_signed_in policy_signed_in = {
        .session_handle = (*out).session_handle,
        .curve_type = BNP_256,
        .digest = messages[2],
        .signature_r = (*sign_out).signature_r,
        .signature_s = (*sign_out).signature_s,
        .public_key = &public_key
    };
    ubi_policy_signed(&policy_signed_in, NULL);
    ubi_buffer *policy_digest = NULL;
    result = ubi_get_policy_digest((*out).session_handle, &policy_digest);
    printf("SHA256 Digest: ");
    for (size_t i = 0; i < policy_digest->buffer_len; i++) {
        printf("%02x", policy_digest->buffer[i]);
    }     
    
    printf("\n%d\n", result);   
    // Free the allocated memory
    if (out != NULL) {
        free_ubi_start_policy_session_out(out);
    }
    free((*sha_out).digest->buffer);
    free((*sha_out).digest);
    free(sha_out);
    free((*sign_out).signature_r->buffer);
    free((*sign_out).signature_r);
    free((*sign_out).signature_s->buffer);
    free((*sign_out).signature_s);
    free(sign_out);
    free(policy_digest->buffer);
    free(policy_digest);
    for (int i = 0; i < 3; i++) {
        free(messages[i]);
    }
    free(messages);
    return result;
}