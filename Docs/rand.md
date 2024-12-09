# UBI Random Documentation

This header file defines the function used for generating random bytes in the UBI Crypt library.

## Functions

### `int ubi_random_bytes(void *p_rng, unsigned char *output, size_t bytes_num)`

This function generates a specified number of random bytes.

- **Parameters:**
  - `void *p_rng`: A pointer to the random number generator context. This parameter can be `NULL` if not used.
  - `unsigned char *output`: A pointer to the buffer where the generated random bytes will be stored.
  - `size_t bytes_num`: The number of random bytes to generate.

- **Returns:**
  - `UBI_SUCCESS` on success.
  - `UBI_RAND_ERROR` if there is an error during random byte generation.

## Usage

Include this header file in your source code to use the random byte generation function:

```C
#include <ubi_crypt/rand.h>