# UBI RSA Documentation

This library provides data structures and functions for performing RSA encryption and decryption operations in the UBI Crypt library. It defines input and output types for both encryption and decryption, as well as functions to execute these operations.

---

## Structures

### 1. `ubi_rsa_encrypt_in`
- **Description**: Input parameters for RSA encryption.
- **Fields**:
  - `struct ubi_buffer *public_key`: Buffer containing the RSA public key.
  - `struct ubi_buffer *public_key_exponent`: Buffer containing the RSA public key exponent.
  - `struct ubi_buffer *plaintext`: Buffer containing the plaintext to be encrypted.

---

### 2. `ubi_rsa_encrypt_out`
- **Description**: Output parameters for RSA encryption.
- **Fields**:
  - `struct ubi_buffer *ciphertext`: Buffer containing the resulting ciphertext.

---

### 3. `ubi_rsa_decrypt_in`
- **Description**: Input parameters for RSA decryption.
- **Fields**:
  - `struct ubi_buffer *private_exponent`: Buffer containing the RSA private exponent.
  - `struct ubi_buffer *rsa_modulus`: Buffer containing the RSA modulus.
  - `struct ubi_buffer *public_key_exponent`: Buffer containing the RSA public key exponent.
  - `struct ubi_buffer *ciphertext`: Buffer containing the ciphertext to be decrypted.

---

### 4. `ubi_rsa_decrypt_out`
- **Description**: Output parameters for RSA decryption.
- **Fields**:
  - `struct ubi_buffer *plaintext`: Buffer containing the resulting plaintext.

---

## Functions

### 1. `int ubi_rsa_encrypt(struct ubi_rsa_encrypt_in *in, struct ubi_rsa_encrypt_out **out)`
- **Description**: Performs RSA encryption.
- **Parameters**:
  - `struct ubi_rsa_encrypt_in *in`: Pointer to the structure containing encryption input parameters.
  - `struct ubi_rsa_encrypt_out **out`: Pointer to a pointer to the structure that will hold the encryption output.
- **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

### 2. `int ubi_rsa_decrypt(struct ubi_rsa_decrypt_in *in, struct ubi_rsa_decrypt_out **out)`
- **Description**: Performs RSA decryption.
- **Parameters**:
  - `struct ubi_rsa_decrypt_in *in`: Pointer to the structure containing decryption input parameters.
  - `struct ubi_rsa_decrypt_out **out`: Pointer to a pointer to the structure that will hold the decryption output.
- **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

## Usage Example

### RSA Encryption Example

```c
#include <ubi_rsa.h>

