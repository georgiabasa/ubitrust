# UBI AES Documentation

This header file defines the structures and functions used for AES encryption and decryption in the UBI Crypt library.

## Structures

### `ubi_aes128_enc_in`

This structure represents the input for AES-128 encryption.

- `struct ubi_buffer *plaintext`: The plaintext data to be encrypted.
- `struct ubi_buffer *key`: The encryption key.
- `uint8_t iv[IV_SIZE]`: The initialization vector (IV) used for encryption.

### `ubi_aes128_enc_out`

This structure represents the output of AES-128 encryption.

- `struct ubi_buffer *ciphertext`: The resulting ciphertext after encryption.
- `uint8_t iv[IV_SIZE]`: The initialization vector (IV) used for encryption.

### `ubi_aes128_dec_in`

This structure represents the input for AES-128 decryption.

- `struct ubi_buffer *ciphertext`: The ciphertext data to be decrypted.
- `struct ubi_buffer *key`: The decryption key.
- `uint8_t iv[IV_SIZE]`: The initialization vector (IV) used for decryption.

### `ubi_aes128_dec_out`

This structure represents the output of AES-128 decryption.

- `struct ubi_buffer *plaintext`: The resulting plaintext after decryption.

## Functions

### `void free_ubi_aes128_enc_out(struct ubi_aes128_enc_out *enc_out)`

This function frees the memory allocated for an `ubi_aes128_enc_out` structure.

- `enc_out`: A pointer to the `ubi_aes128_enc_out` structure to be freed.

### `void free_ubi_aes128_dec_out(struct ubi_aes128_dec_out *dec_out)`

This function frees the memory allocated for an `ubi_aes128_dec_out` structure.

- `dec_out`: A pointer to the `ubi_aes128_dec_out` structure to be freed.

### `int ubi_aes_encrypt(struct ubi_aes128_enc_in *in, struct ubi_aes128_enc_out **out)`

This function performs AES-128 encryption.

- `in`: A pointer to the `ubi_aes128_enc_in` structure containing the input data for encryption.
- `out`: A pointer to a pointer to the `ubi_aes128_enc_out` structure that will contain the output data after encryption.

### `int ubi_aes_decrypt(struct ubi_aes128_dec_in *in, struct ubi_aes128_dec_out **out)`

This function performs AES-128 decryption.

- `in`: A pointer to the `ubi_aes128_dec_in` structure containing the input data for decryption.
- `out`: A pointer to a pointer to the `ubi_aes128_dec_out` structure that will contain the output data after decryption.

## Usage

Include this header file in your source code to use the AES encryption and decryption functions and structures.

```C
#include <ubi_crypt/aes.h>