# UBITRUST ECDSA Documentation

This header file defines the structures and functions used for ECDSA (Elliptic Curve Digital Signature Algorithm) operations in the UBITRUST Crypt library.

## Structures

### `ubi_ecdsa_sign_in`
This structure represents the input for ECDSA signing.
- `int curve_type`: The type of elliptic curve to be used.
- `struct ubi_buffer *private_key`: The private key used for signing.
- `struct ubi_buffer *digest`: The digest of the message to be signed.

### `ubi_ecdsa_sign_out`
This structure represents the output of ECDSA signing.
- `struct ubi_buffer *signature_r`: The `r` component of the ECDSA signature.
- `struct ubi_buffer *signature_s`: The `s` component of the ECDSA signature.

### `ubi_ecdsa_verify_in`
This structure represents the input for ECDSA verification.
- `int curve_type`: The type of elliptic curve to be used.
- `struct ubi_buffer *public_key`: The public key used for verification.
- `struct ubi_buffer *digest`: The digest of the message to be verified.
- `struct ubi_buffer *signature_r`: The `r` component of the ECDSA signature.
- `struct ubi_buffer *signature_s`: The `s` component of the ECDSA signature.

### `ubi_ecdsa_verify_out`
This structure represents the output of ECDSA verification.
- `size_t verification_status`: The status of the verification (0 for success, non-zero for failure).

## Functions

### `void free_ubi_ecdsa_sign_out(struct ubi_ecdsa_sign_out *sign_out)`
This function frees the memory allocated for an `ubi_ecdsa_sign_out` structure.
- `sign_out`: A pointer to the `ubi_ecdsa_sign_out` structure to be freed.

### `int ubi_ecdsa_sign(struct ubi_ecdsa_sign_in *in, struct ubi_ecdsa_sign_out **out)`
This function performs ECDSA signing.
- `in`: A pointer to the `ubi_ecdsa_sign_in` structure containing the input data for signing.
- `out`: A pointer to a pointer to the `ubi_ecdsa_sign_out` structure that will contain the output data after signing.

### `int ubi_ecdsa_verify(struct ubi_ecdsa_verify_in *in, struct ubi_ecdsa_verify_out *out)`
This function performs ECDSA verification.
- `in`: A pointer to the `ubi_ecdsa_verify_in` structure containing the input data for verification.
- `out`: A pointer to the `ubi_ecdsa_verify_out` structure that will contain the output data after verification.

## Usage

Include this header file in your source code to use the ECDSA functions and structures:
```C
#include <ubi_crypt/ecdsa.h>