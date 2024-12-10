# UBITRUST Hash Documentation

This header file defines the structures and functions used for SHA-256 hashing in the UBITRUST Crypt library.

## Structures

### `ubi_sha_in`

This structure represents the input for SHA-256 hashing.

- `struct ubi_buffer *messages`: An array of messages to be hashed.
- `size_t messages_len`: The number of messages in the array.

### `ubi_sha_out`

This structure represents the output of SHA-256 hashing.

- `struct ubi_buffer *digest`: The resulting SHA-256 digest.

## Functions

### `void free_ubi_sha_out(struct ubi_sha_out *out)`

This function frees the memory allocated for a `ubi_sha_out` structure.

- `out`: A pointer to the `ubi_sha_out` structure to be freed.

### `int ubi_sha256(struct ubi_sha_in *in, struct ubi_sha_out **out)`

This function performs SHA-256 hashing.

- `in`: A pointer to the `ubi_sha_in` structure containing the input data for hashing.
- `out`: A pointer to a pointer to the `ubi_sha_out` structure that will contain the output data after hashing.

## Usage

Include this header file in your source code to use the SHA-256 hashing functions and structures.
```C
#include <ubi_crypt/hash.h>