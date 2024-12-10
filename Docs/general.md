# UBITRUST general info

This file will provide some additional information about the UBITRUST library.

## Build details

When building the UBITRUST library, by running for example this command on the main folder:

`make MODE=debug BUILD_TEST=1`

the latest mbedtls 3.6.x is being downloaded and built, and after that the UBITRUST specific .o and .a files are produced, along with executable tests (configured with the `BUILD_TEST` flag)

Specifically, the main folder after building, should have the following subfolders and files:

- `build`: where mbedtls, .o and .a files, and tests (if configured),  are stored

- `Docs`: all .md function specific and more general files with descriptions and instructions

- `include`: all .h files needed for UBITRUST operation, both in ubi_common for general macros and definitions, and ubi_crypt for crypto specific functions

- `src`: the source .c files

- `test`: the source .c test files

- `debug.sh`: a bash script that runs all tests with valgrind to ensure functionality and memory-leak free operation

- `Makefile`: the makefile of UBITRUST

- `README.md`: the main readme of UBITRUST

## Code-specfic general information

### `ubi_buffer`

This structure is commonly used throughout the UBITRUST library, defined in include/ubi_common/structs.h, and it is comprised by a uint8_t pointer to a dynamically allocated buffer and a size_t field, for the size of the buffer.

### `Errors`

Errors in UBITRUST are well defined, and put in strategic places throughout the whole code to correctly identify any problems and resolve them. Errors are defined in include/ubi_common/errors.h

#### General Success

`UBI_SUCCESS` (0): Operation completed successfully without any errors.

#### Memory Errors

`UBI_MEM_ERROR` (-1): Indicates a memory allocation failure, likely due to insufficient system memory.

`UBI_CPY_ERROR` (-2): Indicates a memory copying failure, possibly due to invalid source or destination pointers or buffer overflows.

#### Initialization Errors

`UBI_INIT_ERROR` (-3): Occurs during initialization of a library component.

#### Cryptographic Errors

`UBI_AES_ERROR` (-4): Failure in AES encryption or decryption.

`UBI_PADDING_ERROR` (-5): Indicates an issue with cryptographic padding in symmetric encryption/decryption.

`UBI_SIGN_ERROR` (-6): Error while generating a digital signature.

`UBI_VERIFY_ERROR` (-7): Failure in verifying a digital signature.

`UBI_SHA256_ERROR` (-8): Error while computing a SHA-256 hash.

`UBI_HMAC_ERROR` (-9): Indicates a failure in HMAC computation.

`UBI_MOD_ERROR` (-10): Modular arithmetic error.

`UBI_RAND_ERROR` (-11): Error in generating random numbers.

`UBI_ECP_MUL_ERROR` (-14): Error during elliptic curve point multiplication.

`UBI_RSA_DEC_ERROR` (-19): Failure in RSA decryption.

`UBI_RSA_ENC_ERROR` (-21): RSA encryption failure.

`UBI_KDF_ERROR` (-20): Error in Key Derivation Function.

`UBI_RANDOM_BYTES_MOD_ERROR` (-23): Error while generating modular random bytes.

`UBI_ECP_ADD_ERROR` (-24): Failure during elliptic curve point addition.

#### File I/O Errors

`UBI_READ_BIN_ERROR` (-12): Error reading binary data from a file.

`UBI_WRITE_BIN_ERROR` (-13): Failure in writing binary data to a file.

#### Other Errors

`UBI_LOAD_ERROR` (-15): General failure in loading a resource.

`UBI_POLICY_START_ERROR` (-16): Failure to start a policy.

`UBI_POLICY_SIGNED_ERROR` (-17): Indicates a problem in policy signed function.

`UBI_AUTHENTICATION_ERROR` (-18): Failure in authentication.

`UBI_INVALID_POLICY_HANDLE` (-22): Error due to an invalid policy handle.

#### Feature Not Implemented

`UBI_NOT_IMPLEMENTED_ERROR` (1): Indicates that the requested feature or function is not yet implemented in the library.