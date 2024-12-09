#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <ubi_crypt/rsa.h>

#include <ubi_common/macros.h>
#include <ubi_common/structs.h>

#define RSA_KEY_LENGTH 256  // The length of the RSA key components

int main(void) 
{
    uint8_t private_exponent[256] = {0x29,0x3F,0x4D,0xBA,0x03,0x79,0x07,0xB7,0xB6,0xB2,0x22,0xDF,0xAC,0xA6,0xA4,0xF2,0xEB,0x4B,0x9A,0xF6,0x14,0xDF,0x1A,0x93,0xFB,0x3C,0xC0,0x00,0x95,0x14,0x86,0xF4,0x1B,0xDC,0x44,0x90,0x84,0x69,0x78,0xDD,0x76,0x41,0x1E,0xDC,0x21,0xA2,0xAF,0x70,0x52,0xBC,0xD1,0x63,0xAD,0xAC,0x5C,0xE8,0x94,0xA9,0x49,0xD8,0x68,0x8E,0xF8,0xD3,0xD8,0xD9,0x30,0xA8,0xBA,0x78,0xA4,0xDE,0xE5,0xD6,0xE8,0xC5,0xAC,0x9D,0xE7,0x67,0x8D,0x21,0x98,0xBE,0x36,0x0B,0xF0,0xED,0x86,0x6A,0xB8,0x11,0x2B,0xDC,0x7D,0xF4,0x59,0x90,0xE5,0xF9,0x53,0x2D,0xC4,0x1D,0x5D,0x8E,0x25,0x97,0xBD,0xAB,0x15,0x8F,0xFF,0x6D,0x34,0xDD,0x2C,0x7E,0xA1,0xBD,0x00,0x5F,0xA0,0x94,0xA1,0x3F,0xED,0xC1,0x9C,0x27,0x5B,0x3E,0xF4,0xEF,0x3A,0xA4,0x36,0x68,0x2C,0x39,0xD9,0xAC,0xB7,0x2A,0xD3,0x43,0xEB,0x98,0x70,0x55,0x91,0xB4,0xF3,0x1B,0x40,0xC6,0x84,0xAC,0xD5,0xDF,0x6B,0x30,0x89,0x99,0x89,0x96,0x53,0x3C,0x3A,0x9F,0x4F,0x96,0xD0,0xAC,0xE0,0x0A,0xFA,0x4A,0xE1,0xDE,0x39,0x18,0xA9,0x38,0x9D,0xFE,0xC5,0x9E,0x25,0x8F,0x1A,0x56,0x4D,0x91,0x86,0x0A,0xA6,0xDC,0x8B,0xDF,0x84,0x6F,0x89,0x33,0x89,0xAD,0x52,0x98,0x63,0xC8,0xC7,0x2B,0xE2,0x40,0xDB,0x42,0xF4,0x30,0xEF,0xB9,0xF5,0x1E,0xDF,0x8E,0x4E,0xCD,0xAC,0x51,0xB5,0x34,0xB1,0x12,0xCD,0x39,0x62,0x3C,0x1B,0x09,0xB6,0xAA,0xA1,0x5D,0x1E,0x13,0x30,0x27,0x98,0xDC,0xCB,0x46,0x14,0xCA,0x1E,0x06,0x4E,0x31};
    uint8_t rsa_modulus[256] = {0xC7,0xA5,0xAE,0x58,0xCF,0x47,0x13,0x25,0xDC,0x09,0x41,0x9A,0x7F,0xA0,0xBD,0x40,0x0F,0xB3,0xE2,0xB0,0x35,0xA4,0x7A,0xE0,0xB9,0x73,0xFF,0xA5,0xA5,0x31,0x28,0x9F,0xC7,0x70,0x03,0x44,0x4F,0x72,0x5F,0x92,0xC6,0xDF,0xCD,0xBB,0x30,0x27,0x0B,0x53,0x4E,0xAC,0xA9,0x1C,0xF2,0x9D,0x5A,0xC5,0x6B,0x0C,0x73,0x49,0xEF,0x0C,0x33,0xC8,0x5E,0xA1,0x44,0x54,0x01,0x89,0xDB,0x63,0x33,0x01,0xDD,0x4C,0x42,0x51,0x4C,0xDD,0x86,0x1C,0x17,0xE5,0x0D,0xBA,0xB4,0xA0,0x78,0x40,0xB5,0x6D,0xCF,0x67,0x1D,0x6F,0x64,0x00,0xE6,0x1A,0x09,0xA9,0xC5,0x5F,0x3F,0x37,0x31,0x31,0x99,0x0C,0x63,0x6E,0xE3,0x96,0x33,0xC6,0x3E,0xFE,0x87,0x97,0xF9,0xE2,0xD3,0x62,0x6D,0x24,0x34,0xF9,0xB9,0x43,0x61,0x9D,0x8D,0xA5,0xDA,0x99,0xE0,0xCA,0x5E,0x86,0xA9,0xFF,0xDB,0x6B,0x54,0xBD,0xCD,0x29,0xE2,0xC0,0x6C,0x9F,0xE3,0x42,0x34,0x6B,0xE8,0x88,0x95,0x9D,0x67,0x40,0x89,0x8A,0xC3,0x88,0x7B,0x16,0xAC,0x7C,0x1C,0x17,0x11,0x1C,0x17,0x05,0x0F,0xCA,0xB6,0x59,0xCF,0x1F,0xF0,0x4D,0xD3,0xAF,0xEB,0x7F,0xA0,0x55,0xEB,0x10,0x1A,0x84,0x8D,0xF8,0xF0,0x25,0x01,0x45,0x89,0xA0,0x00,0x81,0xDB,0x59,0xFF,0xA0,0x3B,0x7D,0xF5,0xEA,0x9C,0x90,0xC9,0xC9,0xED,0x3E,0xE9,0x28,0x1E,0xAE,0xA2,0x3B,0x94,0x8B,0x4B,0x42,0xE8,0x50,0x07,0x6F,0xC8,0xF0,0xE0,0x3A,0x99,0x61,0x8B,0x29,0x13,0xDD,0xF6,0xA2,0x58,0xAF,0xCB,0x28,0x0E,0x84,0x0E,0x99,0x21,0x37,0x9C,0x55};
    // uint8_t public_exponent[3] = {0x01,0x00,0x02};
    uint8_t public_exponent[3] = {0x01,0x00,0x01};
    struct ubi_buffer *enc_in = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    struct ubi_buffer *dec_in = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));

    struct ubi_rsa_encrypt_in *encrypt_in = (struct ubi_rsa_encrypt_in*)calloc(1,sizeof(struct ubi_rsa_encrypt_in));
    struct ubi_rsa_encrypt_out *encrypt_out = NULL;
    struct ubi_rsa_decrypt_in *decrypt_in = (struct ubi_rsa_decrypt_in*)calloc(1,sizeof(struct ubi_rsa_decrypt_in));
    struct ubi_rsa_decrypt_out *decrypt_out = NULL;

    // Initialize memory for RSA encryption and decryption structures
    (*enc_in).buffer = NULL;
    (*enc_in).buffer_len = 0;
    dec_in->buffer = NULL;
    dec_in->buffer_len = 0;
    encrypt_in->public_key = NULL;
    encrypt_in->public_key_exponent = NULL;
    encrypt_in->plaintext = NULL;
    // encrypt_out->ciphertext = NULL;
    decrypt_in->private_exponent = NULL;
    decrypt_in->rsa_modulus = NULL;
    decrypt_in->public_key_exponent = NULL;
    decrypt_in->ciphertext = NULL;
    // decrypt_out->plaintext = NULL;

    const char *message = "Hello, this is a test message.";
    size_t message_len = strlen(message);

    // Allocate memory for the input and output buffers
    (*enc_in).buffer = (uint8_t*)calloc(1,message_len);
    if (!(*enc_in).buffer) {
        perror("Failed to allocate memory for (*enc_in).buffer");
        exit(EXIT_FAILURE);
    }
    dec_in->buffer = (uint8_t*)calloc(1,RSA_KEY_LENGTH); 
    if (!dec_in->buffer) {
        perror("Failed to allocate memory for dec_in->buffer");
        exit(EXIT_FAILURE);
    }

    (*enc_in).buffer_len = message_len;
    dec_in->buffer_len = RSA_KEY_LENGTH;

    // Copy data to the encrypt_in struct
    encrypt_in->public_key = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    if (!encrypt_in->public_key) {
        perror("Failed to allocate memory for encrypt_in->public_key");
        exit(EXIT_FAILURE);
    }
    encrypt_in->public_key->buffer = (uint8_t*)calloc(1,RSA_KEY_LENGTH);
    if (!encrypt_in->public_key->buffer) {
        perror("Failed to allocate memory for encrypt_in->public_key->buffer");
        exit(EXIT_FAILURE);
    }
    encrypt_in->public_key->buffer_len = RSA_KEY_LENGTH;

    encrypt_in->public_key_exponent = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
    if (!encrypt_in->public_key_exponent) {
        perror("Failed to allocate memory for encrypt_in->public_key_exponent");
        exit(EXIT_FAILURE);
    }
    encrypt_in->public_key_exponent->buffer = (uint8_t*)calloc(1,3);
    if (!encrypt_in->public_key_exponent->buffer) {
        perror("Failed to allocate memory for encrypt_in->public_key_exponent->buffer");
        exit(EXIT_FAILURE);
    }
    encrypt_in->public_key_exponent->buffer_len = 3;

    memcpy(encrypt_in->public_key->buffer, rsa_modulus, RSA_KEY_LENGTH);
    memcpy((*enc_in).buffer, message, message_len);
    memcpy(encrypt_in->public_key_exponent->buffer, public_exponent, 3);

    encrypt_in->plaintext = enc_in;

    

    // Perform encryption
    int ret = ubi_rsa_encrypt(encrypt_in, &encrypt_out);
    if (ret == 0) 
    {
        printf("Encrypted message (hex):\n");
        for (size_t i = 0; i < encrypt_out->ciphertext->buffer_len; i++) {
            printf("%02X", encrypt_out->ciphertext->buffer[i]);
        }
        printf("\n");

        // Copy data to the decrypt_in struct
        decrypt_in->private_exponent = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
        if (!decrypt_in->private_exponent) {
            perror("Failed to allocate memory for decrypt_in->private_exponent");
            exit(EXIT_FAILURE);
        }
        decrypt_in->private_exponent->buffer = (uint8_t*)calloc(1,RSA_KEY_LENGTH);
        if (!decrypt_in->private_exponent->buffer) {
            perror("Failed to allocate memory for decrypt_in->private_exponent->buffer");
            exit(EXIT_FAILURE);
        }
        decrypt_in->private_exponent->buffer_len = RSA_KEY_LENGTH;

        decrypt_in->rsa_modulus = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
        if (!decrypt_in->rsa_modulus) {
            perror("Failed to allocate memory for decrypt_in->rsa_modulus");
            exit(EXIT_FAILURE);
        }
        decrypt_in->rsa_modulus->buffer = (uint8_t*)calloc(1,RSA_KEY_LENGTH);
        if (!decrypt_in->rsa_modulus->buffer) {
            perror("Failed to allocate memory for decrypt_in->rsa_modulus->buffer");
            exit(EXIT_FAILURE);
        }
        decrypt_in->rsa_modulus->buffer_len = RSA_KEY_LENGTH;

        decrypt_in->public_key_exponent = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
        if (!decrypt_in->public_key_exponent) {
            perror("Failed to allocate memory for decrypt_in->public_key_exponent");
            exit(EXIT_FAILURE);
        }
        decrypt_in->public_key_exponent->buffer = (uint8_t*)calloc(1,3);
        if (!decrypt_in->public_key_exponent->buffer) {
            perror("Failed to allocate memory for decrypt_in->public_key_exponent->buffer");
            exit(EXIT_FAILURE);
        }
        decrypt_in->public_key_exponent->buffer_len = 3;

        decrypt_in->ciphertext = (struct ubi_buffer*)calloc(1,sizeof(struct ubi_buffer));
        if (!decrypt_in->ciphertext) {
            perror("Failed to allocate memory for decrypt_in->ciphertext");
            exit(EXIT_FAILURE);
        }
        decrypt_in->ciphertext->buffer = (uint8_t*)calloc(1,encrypt_out->ciphertext->buffer_len);
        if (!decrypt_in->ciphertext->buffer) {
            perror("Failed to allocate memory for decrypt_in->ciphertext->buffer");
            exit(EXIT_FAILURE);
        }
        decrypt_in->ciphertext->buffer_len = encrypt_out->ciphertext->buffer_len;

        memcpy(decrypt_in->rsa_modulus->buffer, rsa_modulus, RSA_KEY_LENGTH);
        memcpy(decrypt_in->ciphertext->buffer, encrypt_out->ciphertext->buffer, encrypt_out->ciphertext->buffer_len);
        memcpy(decrypt_in->public_key_exponent->buffer, public_exponent, 3); 
        memcpy(decrypt_in->private_exponent->buffer, private_exponent, RSA_KEY_LENGTH); 

        // Perform decryption
        ret = ubi_rsa_decrypt(decrypt_in, &decrypt_out);
        if (ret == 0) {
            printf("Decrypted message: %.*s\n", (int)decrypt_out->plaintext->buffer_len, decrypt_out->plaintext->buffer);
        }
    }

    // Free allocated memory
    if (enc_in) {
        if ((*enc_in).buffer) free((*enc_in).buffer);
        free(enc_in);
    }

    if (dec_in) {
        if (dec_in->buffer) free(dec_in->buffer);
        free(dec_in);
    }

    if (encrypt_in) {
        if (encrypt_in->public_key) {
            if (encrypt_in->public_key->buffer) free(encrypt_in->public_key->buffer);
            free(encrypt_in->public_key);
        }
        if (encrypt_in->public_key_exponent) {
            if (encrypt_in->public_key_exponent->buffer) free(encrypt_in->public_key_exponent->buffer);
            free(encrypt_in->public_key_exponent);
        }
        free(encrypt_in);
    }
    free_ubi_rsa_encrypt_out(encrypt_out);
    

    if (decrypt_in) {
        if (decrypt_in->private_exponent) {
            if (decrypt_in->private_exponent->buffer) free(decrypt_in->private_exponent->buffer);
            free(decrypt_in->private_exponent);
        }
        if (decrypt_in->rsa_modulus) {
            if (decrypt_in->rsa_modulus->buffer) free(decrypt_in->rsa_modulus->buffer);
            free(decrypt_in->rsa_modulus);
        }
        if (decrypt_in->public_key_exponent) {
            if (decrypt_in->public_key_exponent->buffer) free(decrypt_in->public_key_exponent->buffer);
            free(decrypt_in->public_key_exponent);
        }
        if (decrypt_in->ciphertext) {
            if (decrypt_in->ciphertext->buffer) free(decrypt_in->ciphertext->buffer);
            free(decrypt_in->ciphertext);
        }
        free(decrypt_in);
    }
    free_ubi_rsa_decrypt_out(decrypt_out);  
    


    return 0;
}
