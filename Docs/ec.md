# UBI EC Documentation

This header file defines the structures and functions used for elliptic curve operations in the UBI Crypt library.



## Functions

### `int ubi_get_ec_group_bnp256(mbedtls_ecp_group **grp)`

This function initializes an elliptic curve group for the BNP-256 curve.

- **Parameters:**
  - `mbedtls_ecp_group **grp`: A pointer to a pointer to an `mbedtls_ecp_group` structure that will be initialized.

- **Returns:**
  - `UBI_SUCCESS` on success.
  - `UBI_INIT_ERROR` if the initialization fails.

---

### `int free_ubi_ecp_group(mbedtls_ecp_group *grp)`

This function frees the memory allocated for an elliptic curve group.

- **Parameters:**
  - `mbedtls_ecp_group *grp`: A pointer to the `mbedtls_ecp_group` structure to be freed.

---

### `int ubi_get_ecp_size(mbedtls_ecp_point *ecp, size_t *ecp_size)`

This function retrieves the size of an elliptic curve point.

- **Parameters:**
  - `mbedtls_ecp_point *ecp`: A pointer to the `mbedtls_ecp_point` structure.
  - `size_t *ecp_size`: A pointer to a `size_t` variable that will store the size of the elliptic curve point.

---

## Usage

Include this header file in your source code to use the elliptic curve functions and structures:

```c
#include <ubi_crypt/ec.h>
