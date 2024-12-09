#ifndef __UBI_ERRORS_H__
#define __UBI_ERRORS_H__

// General Success
#define UBI_SUCCESS 0

// Memory Errors
#define UBI_MEM_ERROR -1
#define UBI_CPY_ERROR -2

// Initialization Errors
#define UBI_INIT_ERROR -3

// Cryptographic Errors
#define UBI_AES_ERROR -4
#define UBI_PADDING_ERROR -5
#define UBI_SIGN_ERROR -6
#define UBI_VERIFY_ERROR -7
#define UBI_SHA256_ERROR -8
#define UBI_HMAC_ERROR -9
#define UBI_MOD_ERROR -10
#define UBI_RAND_ERROR -11

// File I/O Errors
#define UBI_READ_BIN_ERROR -12
#define UBI_WRITE_BIN_ERROR -13

#define UBI_ECP_MUL_ERROR -14

#define UBI_LOAD_ERROR -15

#define UBI_POLICY_START_ERROR -16

#define UBI_POLICY_SIGNED_ERROR -17

#define UBI_AUTHENTICATION_ERROR -18    

#define UBI_RSA_DEC_ERROR -19

#define UBI_KDF_ERROR -20   

#define UBI_RSA_ENC_ERROR -21   

#define UBI_INVALID_POLICY_HANDLE -22   

#define UBI_RANDOM_BYTES_MOD_ERROR -23

#define UBI_ECP_ADD_ERROR -24   
// Feature Not Implemented
#define UBI_NOT_IMPLEMENTED_ERROR 1


#endif
