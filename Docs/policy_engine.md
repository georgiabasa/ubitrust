# UBI Policy Engine Documentation

This library provides structures and functions for managing policy sessions and signed policy validation in the UBI Crypt library. The header defines data types and methods to handle secure sessions, policy signatures, and policy digest calculations.

---

## Structures

### 1. `ubi_policy_session`
- **Description**: Represents a policy session with associated metadata.
- **Fields**:
  - `uint8_t nonce[NONCE_SIZE]`: The nonce used for the session.
  - `uint8_t session_handle[SESSION_HANDLE_SIZE]`: The unique identifier for the session.
  - `uint8_t session_digest[SHA256_DIGEST_LENGTH]`: The digest for the session.

---

### 2. `ubi_start_policy_session_out`
- **Description**: Output parameters for starting a policy session.
- **Fields**:
  - `struct ubi_buffer *nonce`: Buffer containing the session nonce.
  - `struct ubi_buffer *session_handle`: Buffer containing the session handle.

---

### 3. `ubi_policy_signed_in`
- **Description**: Input parameters for validating a signed policy.
- **Fields**:
  - `struct ubi_buffer *session_handle`: Buffer containing the session handle.
  - `int curve_type`: Type of elliptic curve used for the signature.
  - `struct ubi_buffer *digest`: Buffer containing the policy digest.
  - `struct ubi_buffer *signature_r`: Buffer containing the `r` component of the signature.
  - `struct ubi_buffer *signature_s`: Buffer containing the `s` component of the signature.
  - `struct ubi_buffer *public_key`: Buffer containing the public key used to verify the signature.

---

## Functions

### Memory Management
- **`int alloc_ubi_start_policy_session_out(struct ubi_start_policy_session_out **out)`**
  - Allocates memory for a `ubi_start_policy_session_out` structure.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

- **`int free_ubi_start_policy_session_out(struct ubi_start_policy_session_out *out)`**
  - Frees memory allocated for a `ubi_start_policy_session_out` structure.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

### Policy Session Management
- **`int ubi_start_policy_session(void *in, struct ubi_start_policy_session_out **out)`**
  - Starts a policy session using the provided input parameters.
  - **Parameters**:
    - `void *in`: Pointer to the input data.
    - `struct ubi_start_policy_session_out **out`: Pointer to the output structure.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

### Policy Signature Verification
- **`int ubi_policy_signed(struct ubi_policy_signed_in *in, void *out)`**
  - Validates a signed policy using the provided input parameters.
  - **Parameters**:
    - `struct ubi_policy_signed_in *in`: Pointer to the input structure containing the signature and related data.
    - `void *out`: Pointer to the output data (implementation-defined).
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

### Policy Digest Retrieval
- **`int ubi_get_policy_digest(ubi_buffer *in, ubi_buffer **out)`**
  - Computes and retrieves the policy digest.
  - **Parameters**:
    - `ubi_buffer *in`: Pointer to the input buffer containing the policy data.
    - `ubi_buffer **out`: Pointer to a buffer where the computed digest will be stored.
  - **Returns**: `UBI_SUCCESS` on success, or an error code on failure.

---

## Usage Example

Include this header file in your source code to utilize the UBI Policy Engine functionality:

```c
#include <ubi_policy_engine.h>

