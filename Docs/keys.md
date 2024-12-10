# UBITRUST Keys Library Documentation

This library provides data structures and functions to support cryptographic key operations, including public key computation, attestation key management, and migratable key handling. Below is an overview of the structures and functions defined in the header file.

---

## Structures

### 1. `ubi_compute_public_key_in`
- **Description**: Input parameters for computing a public key.
- **Fields**:
  - `int curve_type`: The type of elliptic curve to be used.
  - `struct ubi_buffer *private_key`: Pointer to a buffer containing the private key.

---

### 2. `ubi_compute_public_key_out`
- **Description**: Output of public key computation.
- **Fields**:
  - `struct ubi_buffer *public_key`: Pointer to a buffer containing the computed public key.

---

### 3. `ubi_create_attestation_key_in`
- **Description**: Input parameters for creating an attestation key.
- **Fields**:
  - `int curve_type`: The type of elliptic curve to be used.
  - `struct ubi_buffer *policy`: Pointer to a buffer containing the policy.

---

### 4. `ubi_create_attestation_key_out`
- **Description**: Output of attestation key creation.
- **Fields**:
  - `struct ubi_buffer *seed`: Pointer to a buffer containing the key seed.
  - `struct ubi_buffer *hash_private_key`: Pointer to a buffer containing the hash of the private key.
  - `struct ubi_buffer *name`: Pointer to a buffer containing the name of the key.
  - `struct ubi_buffer *public_key`: Pointer to a buffer containing the public key.

---

### 5. `ubi_load_attestation_key_in`
- **Description**: Input parameters for loading an attestation key.
- **Fields**:
  - `struct ubi_buffer *policy`: Pointer to a buffer containing the policy.
  - `struct ubi_buffer *seed`: Pointer to a buffer containing the key seed.
  - `struct ubi_buffer *hash_private_key`: Pointer to a buffer containing the hash of the private key.

---

### 6. `ubi_load_attestation_key_out`
- **Description**: Output of loading an attestation key.
- **Fields**:
  - `struct ubi_buffer *private_key`: Pointer to a buffer containing the private key.

---

### 7. `ubi_create_migratable_key_in`
- **Description**: Input parameters for creating a migratable key.
- **Fields**:
  - `int curve_type`: The type of elliptic curve to be used.
  - `struct ubi_buffer *policy`: Pointer to a buffer containing the policy.

---

### 8. `ubi_create_migratable_key_out`
- **Description**: Output of migratable key creation.
- **Fields**:
  - `struct ubi_buffer *encrypted_private_key`: Pointer to a buffer containing the encrypted private key.
  - `struct ubi_buffer *hash_private_key`: Pointer to a buffer containing the hash of the private key.
  - `struct ubi_buffer *name`: Pointer to a buffer containing the name of the key.
  - `struct ubi_buffer *public_key`: Pointer to a buffer containing the public key.
  - `uint8_t iv[IV_SIZE]`: Initialization vector for encryption.

---

### 9. `ubi_load_migratable_key_in`
- **Description**: Input parameters for loading a migratable key.
- **Fields**:
  - `struct ubi_buffer *encrypted_private_key`: Pointer to a buffer containing the encrypted private key.
  - `struct ubi_buffer *hash_private_key`: Pointer to a buffer containing the hash of the private key.
  - `struct ubi_buffer *policy`: Pointer to a buffer containing the policy.
  - `uint8_t iv[IV_SIZE]`: Initialization vector for encryption.

---

### 10. `ubi_load_migratable_key_out`
- **Description**: Output of loading a migratable key.
- **Fields**:
  - `struct ubi_buffer *private_key`: Pointer to a buffer containing the private key.

---

## Functions

### Memory Management
- **`void free_ubi_create_attestation_key_out(struct ubi_create_attestation_key_out *out)`**
  - Frees memory allocated for an `ubi_create_attestation_key_out` structure.
  
- **`void free_ubi_load_attestation_key_out(struct ubi_load_attestation_key_out *out)`**
  - Frees memory allocated for an `ubi_load_attestation_key_out` structure.

- **`void free_ubi_create_migratable_key_out(struct ubi_create_migratable_key_out *out)`**
  - Frees memory allocated for an `ubi_create_migratable_key_out` structure.

- **`void free_ubi_load_migratable_key_out(struct ubi_load_migratable_key_out *out)`**
  - Frees memory allocated for an `ubi_load_migratable_key_out` structure.

---

### Key Operations
- **`int ubi_compute_public_key(struct ubi_compute_public_key_in *in, struct ubi_compute_public_key_out **out)`**
  - Computes a public key using the provided private key.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

- **`int ubi_create_attestation_key(struct ubi_create_attestation_key_in *in, struct ubi_create_attestation_key_out **out)`**
  - Creates an attestation key based on the provided input parameters.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

- **`int ubi_load_attestation_key(struct ubi_load_attestation_key_in *in, struct ubi_load_attestation_key_out **out)`**
  - Loads an attestation key using the provided input parameters.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

- **`int ubi_create_migratable_key(struct ubi_create_migratable_key_in *in, struct ubi_create_migratable_key_out **out)`**
  - Creates a migratable key with encryption and associated metadata.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

- **`int ubi_load_migratable_key(struct ubi_load_migratable_key_in *in, struct ubi_load_migratable_key_out **out)`**
  - Loads a migratable key using the encrypted private key and other metadata.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

## Usage Example

Include this header file in your source code to utilize the UBI Keys functionality:

```c
#include <ubi_keys.h>