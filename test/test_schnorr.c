#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ubi_crypt/schnorr.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>

uint8_t private_key_bytes[32] = {
    0x81, 0x02, 0xa8, 0xd7, 0x6c, 0xba, 0x94, 0xe1,
    0x4f, 0xa6, 0x47, 0xc7, 0xe9, 0x49, 0x19, 0x20,
    0x48, 0x2d, 0xfb, 0xf9, 0xbe, 0x04, 0x0d, 0xb7,
    0x27, 0xe6, 0x7c, 0x8e, 0x1d, 0xa1, 0xfa, 0xb2
};

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



uint8_t digest_bytes[32] = {
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    0x0e, 0xe3, 0x90, 0xf3, 0x55, 0x73, 0x50, 0x05,
    0x23, 0x32, 0x13, 0x19, 0x00, 0x92, 0x4a, 0xb6
};


void test_schnorr_signature(void);

void test_schnorr_signature(void){
    ubi_schnorr_sign_in sign_in;
    ubi_schnorr_sign_out *sign_out = NULL;
    int ret;

    struct ubi_buffer private_key = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };
    struct ubi_buffer digest = { .buffer = digest_bytes, .buffer_len = sizeof(digest_bytes) };

    sign_in.private_key = &private_key;
    sign_in.digest = &digest;
    sign_in.curve_type = BNP_256;

    ret = ubi_schnorr_sign(&sign_in, &sign_out);
    if (ret != UBI_SUCCESS) {
        printf("Failed to sign the message. Error code: %d\n", ret);
        return;
    }

    printf("Signature R (%ld bytes): ", (*sign_out).signature_r->buffer_len);
    for (size_t i = 0; i < (*sign_out).signature_r->buffer_len; i++) {
        printf("0x%02x, ", (*sign_out).signature_r->buffer[i]);
    }
    printf("\n");

    printf("Signature S (%ld bytes): ", (*sign_out).signature_s->buffer_len);
    for (size_t i = 0; i < (*sign_out).signature_s->buffer_len; i++) {
        printf("0x%02x, ", (*sign_out).signature_s->buffer[i]);
    }
    printf("\n");


    ubi_schnorr_verify_in verify_in;
    ubi_schnorr_verify_out verify_out;

    struct ubi_buffer public_key = { .buffer = public_key_bytes, .buffer_len = sizeof(public_key_bytes) };

    verify_in.curve_type = BNP_256;
    verify_in.public_key = &public_key;
    verify_in.digest = &digest;
    verify_in.signature_r = (*sign_out).signature_r;
    verify_in.signature_s = (*sign_out).signature_s;

    ret = ubi_schnorr_verify(&verify_in, &verify_out);
    if (ret != UBI_SUCCESS) {
        printf("Failed to verify the signature. Error code: %d\n", ret);
    } else {
        if (verify_out.verification_status == 0) {
            printf("Signature verification succeeded.\n");
        } else {
            printf("Signature verification failed.\n");
        }
    }



    free_ubi_schnorr_signature_out(sign_out);
}

int main(void) {
    test_schnorr_signature();
    return 0;
}

