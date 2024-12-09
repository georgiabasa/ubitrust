#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ubi_crypt/aes.h>

int main(void) {
    // Example key and IV (in a real scenario, these should be securely generated)
    uint8_t key_data[AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8_t iv[IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // Example plaintext
    uint8_t plaintext_data[] = "This is a test message for AES encryption.";
    size_t plaintext_len = strlen((char *)plaintext_data);

    // Key and plaintext buffers
    struct ubi_buffer plaintext = {
        .buffer = plaintext_data,
        .buffer_len = plaintext_len
    };

    struct ubi_buffer key = {
        .buffer = key_data,
        .buffer_len = AES_KEY_SIZE
    };

    // Encryption input and output structures
    struct ubi_aes128_enc_in enc_in = {
        .plaintext = &plaintext,
        .key = &key,
        .iv = {0}
    };
    memcpy(enc_in.iv, iv, IV_SIZE);

    struct ubi_aes128_enc_out *enc_out = NULL;

    // Encrypt the plaintext
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

    // Decryption input and output structures
    struct ubi_aes128_dec_in dec_in = {
        .ciphertext = enc_out->ciphertext,
        .key = &key,
        .iv = {0}
    };
    memcpy(dec_in.iv, enc_out->iv, IV_SIZE);

    struct ubi_aes128_dec_out *dec_out = NULL;

    // Decrypt the ciphertext
    if (ubi_aes_decrypt(&dec_in, &dec_out) == 0) {
        printf("Decryption successful!\nPlaintext: ");
        printf("%.*s\n", (int)dec_out->plaintext->buffer_len, dec_out->plaintext->buffer);
    } else {
        printf("Decryption failed!\n");
        return -1;
    }

    // Free allocated memory
    free_ubi_aes128_enc_out(enc_out);
    free_ubi_aes128_dec_out(dec_out);

    return 0;
}
