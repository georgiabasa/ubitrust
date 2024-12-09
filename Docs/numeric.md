# UBI Numeric Documentation

This header file defines the structures and functions used for numeric operations in the UBI Crypt library.

## Structures

### `ubi_mod_in`
This structure represents the input for the modular operation.
- `struct ubi_buffer *mod`: The modulus value.
- `struct ubi_buffer *input`: The input value to be reduced.

### `ubi_mod_out`
This structure represents the output of the modular operation.
- `struct ubi_buffer *output`: The resulting value after the modular reduction.

## Functions

### `int ubi_mod(struct ubi_mod_in *in, struct ubi_mod_out *out)`
This function performs a modular reduction operation.
- **Parameters:**
  - `in`: A pointer to the `ubi_mod_in` structure containing the input data for the modular operation.
  - `out`: A pointer to the `ubi_mod_out` structure that will contain the output data after the modular operation.
- **Returns:**
  - `UBI_SUCCESS` on success.
  - `UBI_MEM_ERROR` if there is a memory allocation error.
  - `UBI_MOD_ERROR` if there is an error during the modular operation.

## Usage

Include this header file in your source code to use the numeric functions and structures:

```C
#include <ubi_crypt/numeric.h>