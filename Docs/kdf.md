# UBI KDF Documentation

This header file defines the structures and functions used for Key Derivation Function (KDF) operations in the UBI Crypt library.

## Structures

### `ubi_kdf_in`
This structure represents the input for the KDF operation.
- `struct ubi_buffer *seed`: The seed value used for key derivation.
- `struct ubi_buffer *label`: The label used for key derivation.
- `struct ubi_buffer *context_u`: The context value U used for key derivation.
- `struct ubi_buffer *context_v`: The context value V used for key derivation.
- `size_t key_bit_len`: The desired length of the derived key in bits.

### `ubi_kdf_out`
This structure represents the output of the KDF operation.
- `struct ubi_buffer *key`: The derived key.

## Functions

### `void free_ubi_kdf_out(struct ubi_kdf_out *out)`
This function frees the memory allocated for a `ubi_kdf_out` structure.
- `out`: A pointer to the `ubi_kdf_out` structure to be freed.

### `int ubi_kdf_sha256(struct ubi_kdf_in *in, struct ubi_kdf_out **out)`
This function performs key derivation using SHA-256.
- `in`: A pointer to the `ubi_kdf_in` structure containing the input data for key derivation.
- `out`: A pointer to a pointer to the `ubi_kdf_out` structure that will contain the derived key.

## Usage

Include this header file in your source code to use the KDF functions and structures:

```C
#include <ubi_crypt/kdf.h>