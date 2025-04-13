#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <ubi_crypt/aes.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>
#include <ubi_common/errors.h>

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
    uint8_t key_data[AES_KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t *plaintext_data;
    size_t plaintext_len;

    // Hardcoded defaults
    uint8_t default_key[AES_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    uint8_t default_iv[IV_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    const char *default_plaintext = "This is a test message for AES encryption.";

    // Use command-line arguments if provided
    if (argc == 1) {
        // No arguments: use defaults
        memcpy(key_data, default_key, AES_KEY_SIZE);
        memcpy(iv, default_iv, IV_SIZE);
        plaintext_data = (uint8_t *)default_plaintext;
        plaintext_len = strlen(default_plaintext);
    } else if (argc >= 3 && argc <= 4) {
        const char *plaintext_input = argv[1];
        const char *hex_key = argv[2];
        const char *hex_iv = (argc == 4) ? argv[3] : NULL;

        if (hexstr_to_bytes(hex_key, key_data, AES_KEY_SIZE) != 0) {
            fprintf(stderr, "Invalid key format. Expected 64 hex characters.\n");
            return 1;
        }

        if (hex_iv) {
            if (hexstr_to_bytes(hex_iv, iv, IV_SIZE) != 0) {
                fprintf(stderr, "Invalid IV format. Expected 32 hex characters.\n");
                return 1;
            }
        } else {
            memset(iv, 0, IV_SIZE);
        }

        plaintext_data = (uint8_t *)plaintext_input;
        plaintext_len = strlen(plaintext_input);
    } else {
        fprintf(stderr, "Usage: %s [<plaintext> <hex_key_64chars> [hex_iv_32chars]]\n", argv[0]);
        return 1;
    }

    // Plaintext buffer
    struct ubi_buffer plaintext = {
        .buffer = plaintext_data,
        .buffer_len = plaintext_len
    };

    // Key buffer
    struct ubi_buffer key = {
        .buffer = key_data,
        .buffer_len = AES_KEY_SIZE
    };

    // Encryption
    struct ubi_aes128_enc_in enc_in = {
        .plaintext = &plaintext,
        .key = &key,
        .iv = {0}
    };
    memcpy(enc_in.iv, iv, IV_SIZE);

    struct ubi_aes128_enc_out *enc_out = NULL;

    if (ubi_aes_encrypt(&enc_in, &enc_out) == 0) {
        printf("Encryption successful!\nCiphertext: ");
        for (size_t i = 0; i < enc_out->ciphertext->buffer_len; i++) {
            printf("%02x", enc_out->ciphertext->buffer[i]);
        }
        printf("\n");
    } else {
        printf("Encryption failed!\n");
        return -1;
    }

    // Decryption
    struct ubi_aes128_dec_in dec_in = {
        .ciphertext = enc_out->ciphertext,
        .key = &key,
        .iv = {0}
    };
    memcpy(dec_in.iv, enc_out->iv, IV_SIZE);

    struct ubi_aes128_dec_out *dec_out = NULL;

    if (ubi_aes_decrypt(&dec_in, &dec_out) == 0) {
        printf("Decryption successful!\nPlaintext: ");
        printf("%.*s\n", (int)dec_out->plaintext->buffer_len, dec_out->plaintext->buffer);
    } else {
        printf("Decryption failed!\n");
        return -1;
    }

    // Cleanup
    free_ubi_aes128_enc_out(enc_out);
    free_ubi_aes128_dec_out(dec_out);

    return 0;
}
