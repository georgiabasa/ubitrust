#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <ubi_crypt/ecdsa.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>

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
uint8_t evidence_r[32] = {
    0xff, 0x38, 0x2e, 0xcc, 0x75, 0xbb, 0xd2, 0xd2,
    0xac, 0xb8, 0x48, 0x04, 0x48, 0x23, 0xda, 0xdc,
    0xea, 0x36, 0x90, 0xc4, 0x7b, 0xc3, 0x84, 0xda,
    0x67, 0xbb, 0xf2, 0x14, 0x0a, 0xd8, 0x87, 0x86
};
uint8_t evidence_s[32] = {
    0x98, 0x74, 0x4c, 0x0a, 0xdc, 0x08, 0x2d, 0x6c,
    0x79, 0xa0, 0xc0, 0xab, 0x38, 0x5e, 0x77, 0xd0,
    0x4f, 0x69, 0xe0, 0xab, 0x58, 0xe0, 0xb8, 0x1b,
    0x81, 0x9a, 0xf8, 0x0a, 0x91, 0x62, 0x7c, 0x81
};
uint8_t aa_public_key[65] = {
    0x04, 0x1b, 0xe1, 0x65, 0x0b, 0xaf, 0x28, 0x78,
    0x6f, 0x9b, 0x66, 0xc6, 0xfd, 0xdc, 0x1e, 0x75,
    0x05, 0x84, 0xd2, 0xda, 0xec, 0x30, 0xc7, 0xe9,
    0xba, 0xf8, 0x6b, 0x94, 0x89, 0xbc, 0x9f, 0x22,
    0x9c, 0x69, 0x32, 0x79, 0xd8, 0xa0, 0x2e, 0xd0,
    0x20, 0xdf, 0x8d, 0xc2, 0x70, 0x28, 0x43, 0xfd,
    0xdf, 0x80, 0xab, 0x97, 0x9d, 0x72, 0x4b, 0xab,
    0xe1, 0x48, 0x3a, 0xf1, 0xc6, 0x15, 0x64, 0xc9,
    0xc7
};
uint8_t value[32] = {
    0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77,
    0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20,
    0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3,
    0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25
};



// int main(void) {
//     ubi_ecdsa_sign_in sign_in;
//     ubi_ecdsa_sign_out *sign_out = NULL;
//     ubi_ecdsa_verify_in verify_in;
//     ubi_ecdsa_verify_out verify_out;
//     int ret;

//     // Initialize buffers for the input structure
//     struct ubi_buffer private_key = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };
//     struct ubi_buffer digest = { .buffer = value, .buffer_len = sizeof(value) };
//     struct ubi_buffer signature_r_prime = { .buffer = evidence_r, .buffer_len = sizeof(evidence_r) };
//     struct ubi_buffer signature_s_prime = { .buffer = evidence_s, .buffer_len = sizeof(evidence_s) };

//     sign_in.private_key = &private_key;
//     sign_in.digest = &digest;
//     sign_in.curve_type = BNP_256;

//     // Perform ECDSA signing
//     ret = ubi_ecdsa_sign(&sign_in, &sign_out);
//     if (ret != UBI_SUCCESS) {
//         printf("Failed to sign the message. Error code: %d\n", ret);
//         return ret;
//     }

//     // Print the generated signature
//     printf("Signature R (%ld bytes): ", (*sign_out).signature_r->buffer_len);
//     for (size_t i = 0; i < (*sign_out).signature_r->buffer_len; i++) {
//         printf("0x%02x, ", (*sign_out).signature_r->buffer[i]);
//     }
//     printf("\n");

//     printf("Signature S (%ld bytes): ", (*sign_out).signature_s->buffer_len);
//     for (size_t i = 0; i < (*sign_out).signature_s->buffer_len; i++) {
//         printf("0x%02x, ", (*sign_out).signature_s->buffer[i]);
//     }
//     printf("\n");

//     // Initialize buffers for the verification input structure
//     struct ubi_buffer public_key = { .buffer = aa_public_key, .buffer_len = sizeof(aa_public_key) };

//     verify_in.public_key = &public_key;
//     verify_in.digest = &digest;
//     verify_in.signature_r = &signature_r_prime;
//     verify_in.signature_s = &signature_s_prime;
//     verify_in.curve_type = BNP_256;

//     // Perform ECDSA verification
//     ret = ubi_ecdsa_verify(&verify_in, &verify_out);
//     if (ret != UBI_SUCCESS) {
//         printf("Failed to verify the signature. Error code: %d\n", ret);
//     } else {
//         if (verify_out.verification_status == 0) {
//             printf("Signature verification succeeded.\n");
//         } else {
//             printf("Signature verification failed.\n");
//         }
//     }

//     free_ubi_ecdsa_sign_out(sign_out);

//     return 0;
// }

#define HEX_CHAR_TO_BYTE(h, l) ((uint8_t)((isdigit(h) ? h - '0' : tolower(h) - 'a' + 10) << 4 | (isdigit(l) ? l - '0' : tolower(l) - 'a' + 10)))
int hexstr_to_bytes(const char *hexstr, uint8_t *buf, size_t expected_len);

int hexstr_to_bytes(const char *hexstr, uint8_t *buf, size_t expected_len) {
    size_t len = strlen(hexstr);
    if (len != expected_len * 2) return -1;
    for (size_t i = 0; i < expected_len; i++) {
        buf[i] = HEX_CHAR_TO_BYTE(hexstr[2 * i], hexstr[2 * i + 1]);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 6) {
        if (hexstr_to_bytes(argv[1], private_key_bytes, 32) != 0 ||
            hexstr_to_bytes(argv[2], value, 32) != 0 ||
            hexstr_to_bytes(argv[3], evidence_r, 32) != 0 ||
            hexstr_to_bytes(argv[4], evidence_s, 32) != 0 ||
            hexstr_to_bytes(argv[5], aa_public_key, 65) != 0) {
            fprintf(stderr, "Invalid hex input\n");
            return 1;
        }
        printf("Using user-provided values.\n");
    } else {
        printf("Using hardcoded values.\n");
    }

    ubi_ecdsa_sign_in sign_in;
    ubi_ecdsa_sign_out *sign_out = NULL;
    ubi_ecdsa_verify_in verify_in;
    ubi_ecdsa_verify_out verify_out;
    int ret;

    struct ubi_buffer private_key = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };
    struct ubi_buffer digest = { .buffer = value, .buffer_len = sizeof(value) };
    struct ubi_buffer signature_r_prime = { .buffer = evidence_r, .buffer_len = sizeof(evidence_r) };
    struct ubi_buffer signature_s_prime = { .buffer = evidence_s, .buffer_len = sizeof(evidence_s) };

    sign_in.private_key = &private_key;
    sign_in.digest = &digest;
    sign_in.curve_type = BNP_256;

    ret = ubi_ecdsa_sign(&sign_in, &sign_out);
    if (ret != UBI_SUCCESS) {
        printf("Failed to sign the message. Error code: %d\n", ret);
        return ret;
    }

    printf("Signature R (%ld bytes): ", (*sign_out).signature_r->buffer_len);
    for (size_t i = 0; i < (*sign_out).signature_r->buffer_len; i++)
        printf("0x%02x, ", (*sign_out).signature_r->buffer[i]);
    printf("\n");

    printf("Signature S (%ld bytes): ", (*sign_out).signature_s->buffer_len);
    for (size_t i = 0; i < (*sign_out).signature_s->buffer_len; i++)
        printf("0x%02x, ", (*sign_out).signature_s->buffer[i]);
    printf("\n");

    struct ubi_buffer public_key = { .buffer = aa_public_key, .buffer_len = sizeof(aa_public_key) };

    verify_in.public_key = &public_key;
    verify_in.digest = &digest;
    verify_in.signature_r = &signature_r_prime;
    verify_in.signature_s = &signature_s_prime;
    verify_in.curve_type = BNP_256;

    ret = ubi_ecdsa_verify(&verify_in, &verify_out);
    if (ret != UBI_SUCCESS) {
        printf("Failed to verify the signature. Error code: %d\n", ret);
    } else {
        if (verify_out.verification_status == 0) {
            printf("Signature verification succeeded.\n");
        } else {
            printf("Signature verification failed.\n");
        }
    }

    free_ubi_ecdsa_sign_out(sign_out);
    return 0;
}