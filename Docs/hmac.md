# UBI HMAC Documentation

This header file defines the structures and functions used for HMAC-SHA256 operations in the UBI Crypt library.

## Structures

### `ubi_hmac_sha256_in`

This structure represents the input for HMAC-SHA256 hashing.

- `ubi_buffer *messages`: An array of messages to be hashed.
- `size_t messages_len`: The number of messages in the array.
- `ubi_buffer *key`: The key used for HMAC.

### `ubi_hmac_sha256_out`

This structure represents the output of HMAC-SHA256 hashing.

- `ubi_buffer *hmac_digest`: The resulting HMAC digest.

## Functions

### `void free_ubi_hmac_sha256_out(struct ubi_hmac_sha256_out *out)`

This function frees the memory allocated for a `ubi_hmac_sha256_out` structure.

- `out`: A pointer to the `ubi_hmac_sha256_out` structure to be freed.

### `int ubi_hmac_sha256(struct ubi_hmac_sha256_in *in, struct ubi_hmac_sha256_out **out)`

This function performs HMAC-SHA256 hashing.

- `in`: A pointer to the `ubi_hmac_sha256_in` structure containing the input data for hashing.
- `out`: A pointer to a pointer to the `ubi_hmac_sha256_out` structure that will contain the output data after hashing.

## Usage

Include this header file in your source code to use the HMAC-SHA256 hashing functions and structures.

```c
#include <ubi_crypt/hmac.h>