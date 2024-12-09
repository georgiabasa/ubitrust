# UBI Credential Documentation

This header file defines the structures and functions used for credential management in the UBI Crypt library.

## Structures

### `ubi_make_credential_in`
This structure represents the input for creating a credential.
- `struct ubi_buffer *secret`: The secret data to be used in the credential.
- `struct ubi_buffer *key_n`: The RSA public key modulus.
- `struct ubi_buffer *key_e`: The RSA public key exponent.
- `struct ubi_buffer *key_name`: The name of the attestation key.

### `ubi_make_credential_out`
This structure represents the output of creating a credential.
- `struct ubi_buffer *credential`: The resulting credential.
- `struct ubi_buffer *encrypted_secret`: The encrypted secret.
- `struct ubi_buffer *auth_digest`: The authentication digest.
- `uint8_t iv[IV_SIZE]`: The initialization vector (IV) used for encryption.

### `ubi_activate_credential_in`
This structure represents the input for activating a credential.
- `struct ubi_buffer *credential`: The credential to be activated.
- `uint8_t iv[IV_SIZE]`: The initialization vector (IV) used for decryption.
- `struct ubi_buffer *encrypted_random_secret`: The encrypted random secret.
- `struct ubi_buffer *auth_digest`: The authentication digest.
- `struct ubi_buffer *key_name`: The name of the attestation key.

## Functions

### `void free_ubi_make_credential_out(struct ubi_make_credential_out *out)`
This function frees the memory allocated for a `ubi_make_credential_out` structure.
- `out`: A pointer to the `ubi_make_credential_out` structure to be freed.

### `void free_ubi_activate_credential_out(struct ubi_activate_credential_out *out)`
This function frees the memory allocated for a `ubi_activate_credential_out` structure.
- `out`: A pointer to the `ubi_activate_credential_out` structure to be freed.

### `int ubi_make_credential(struct ubi_make_credential_in *in, struct ubi_make_credential_out **out)`
This function creates a credential.
- `in`: A pointer to the `ubi_make_credential_in` structure containing the input data for creating the credential.
- `out`: A pointer to a pointer to the `ubi_make_credential_out` structure that will contain the output data after creating the credential.

### `int ubi_activate_credential(struct ubi_activate_credential_in *in, struct ubi_activate_credential_out **out)`
This function activates a credential.
- `in`: A pointer to the `ubi_activate_credential_in` structure containing the input data for activating the credential.
- `out`: A pointer to a pointer to the `ubi_activate_credential_out` structure that will contain the output data after activating the credential.

## Usage

Include this header file in your source code to use the credential management functions and structures.


```C
#include <ubi_crypt/credential.h>