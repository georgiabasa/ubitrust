#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ubi_crypt/keys.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


void print_ubi_buffer(const ubi_buffer *buf);
void test_ubi_compute_public_key(void);
void test_ubi_create_attestation_key(uint8_t *policy_data, size_t policy_len, int curve_type);
void print_ubi_create_attestation_key_out(const struct ubi_create_attestation_key_out *out);
void print_ubi_create_attestation_key_out(const struct ubi_create_attestation_key_out *out);
void test_ubi_load_attestation_key(void);
void print_ubi_create_migratable_key_in(const struct ubi_create_migratable_key_in *in);
void print_ubi_create_migratable_key_out(const struct ubi_create_migratable_key_out *out);
void print_ubi_load_migratable_key_in(const struct ubi_load_migratable_key_in *in);
void print_ubi_load_migratable_key_out(const struct ubi_load_migratable_key_out *out);




void print_ubi_buffer(const ubi_buffer *buf) {
    if (buf == NULL) {
        printf("Buffer: NULL\n");
        return;
    }
    printf("Buffer Length: %zu\n", buf->buffer_len);
    printf("Buffer Contents: ");
    for (size_t i = 0; i < buf->buffer_len; i++) {
        printf("%02x", buf->buffer[i]);
        if (i < buf->buffer_len - 1) printf(" ");
    }
    printf("\n");
}

void print_ubi_load_migratable_key_out(const struct ubi_load_migratable_key_out *out) {
    if (out == NULL) {
        printf("ubi_load_migratable_key_out is NULL.\n");
        return;
    }

    printf("ubi_load_migratable_key_out:\n");
    printf("  Private Key:\n");
    print_ubi_buffer((*out).private_key);
}


void print_ubi_load_migratable_key_in(const struct ubi_load_migratable_key_in *in) {
    if (in == NULL) {
        printf("ubi_load_migratable_key_in is NULL.\n");
        return;
    }

    printf("ubi_load_migratable_key_in:\n");
    printf("  Encrypted Private Key:\n");
    print_ubi_buffer((*in).encrypted_private_key);
    printf("  Hash Private Key:\n");
    print_ubi_buffer((*in).hash_private_key);
    printf("  Policy:\n");
    print_ubi_buffer((*in).policy);

    printf("  IV: ");
    for (size_t i = 0; i < IV_SIZE; ++i) {
        printf("%02x ",(*in).iv[i]);
    }
    printf("\n");
}

void print_ubi_create_migratable_key_in(const struct ubi_create_migratable_key_in *in) {
    if (in == NULL) {
        printf("ubi_create_migratable_key_in is NULL.\n");
        return;
    }

    printf("ubi_create_migratable_key_in:\n");
    printf("  Curve Type: %d\n",(*in).curve_type);
    printf("  Policy:\n");
    print_ubi_buffer((*in).policy);
}
void print_ubi_create_migratable_key_out(const struct ubi_create_migratable_key_out *out) {
    if (out == NULL) {
        printf("ubi_create_migratable_key_out is NULL.\n");
        return;
    }

    printf("ubi_create_migratable_key_out:\n");
    printf("  Encrypted Private Key:\n");
    print_ubi_buffer((*out).encrypted_private_key);
    printf("  Hash Private Key:\n");
    print_ubi_buffer((*out).hash_private_key);
    printf("  Name:\n");
    print_ubi_buffer((*out).name);
    printf("  Public Key:\n");
    print_ubi_buffer((*out).public_key);

    printf("  IV: ");
    for (size_t i = 0; i < IV_SIZE; ++i) {
        printf("%02x ",(*out).iv[i]);
    }
    printf("\n");
}



void print_ubi_create_attestation_key_out(const struct ubi_create_attestation_key_out *out) {
    if (out == NULL) {
        printf("ubi_create_attestation_key_out: NULL\n");
        return;
    }
    printf("ubi_create_attestation_key_out:\n");
    printf("Seed:\n");
    print_ubi_buffer((*out).seed);
    printf("Hash of Private Key:\n");
    print_ubi_buffer((*out).hash_private_key);
    printf("Name:\n");
    print_ubi_buffer((*out).name);
    printf("Public Key:\\n");
    print_ubi_buffer((*out).public_key);
}

void test_ubi_compute_public_key(void) 
{
    int ret;
    
    // Initialize inputs
    struct ubi_compute_public_key_in in;
    struct ubi_compute_public_key_out *out = NULL;

    uint8_t private_key_data[32] = {
        0x32, 0x54, 0x67, 0x98, 0x21, 0x43, 0x65, 0x87, 
        0x09, 0x87, 0x65, 0x43, 0x21, 0x12, 0x34, 0x56,
        0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 
        0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45
    };

    struct ubi_buffer private_key = {private_key_data, sizeof(private_key_data)};
    in.curve_type = BNP_256;
    in.private_key = &private_key;

    // Call the function
    ret = ubi_compute_public_key(&in, &out);

    // Check the result
    if (ret == UBI_SUCCESS) {
        printf("Public key computed successfully.\n");
        printf("Public key %ld bytes : ", (*out).public_key->buffer_len);
        for (size_t i = 0; i < (*out).public_key->buffer_len; i++) {
            printf("%02X", (*out).public_key->buffer[i]);
        }
        printf("\n");
    } else {
        printf("Failed to compute public key. Error code: %d\n", ret);
    }

    // Clean up
    free((*out).public_key->buffer);
    free((*out).public_key);
    free(out);  
}

void test_ubi_create_attestation_key(uint8_t *policy_data, size_t policy_len, int curve_type) {
    struct ubi_create_attestation_key_in in;
    struct ubi_buffer policy;
    policy.buffer = policy_data;
    policy.buffer_len = policy_len;
    in.policy = &policy;
    in.curve_type = curve_type;

    struct ubi_create_attestation_key_out *out = NULL;
    int result = ubi_create_attestation_key(&in, &out);

    assert(result == UBI_SUCCESS);
    assert(out->seed != NULL);
    assert(out->seed->buffer_len == SHA256_DIGEST_LENGTH);
    assert(out->hash_private_key != NULL);
    assert(out->hash_private_key->buffer_len == SHA256_DIGEST_LENGTH);
    assert(out->public_key != NULL);
    assert(out->public_key->buffer_len == 65);
    assert(out->name != NULL);
    assert(out->name->buffer_len == KEY_NAME_LENGTH);
    assert(out->name->buffer[0] == RH_NULL);
    assert(out->name->buffer[1] == ALG_SHA256);

    printf("Attestation key created successfully.\n");

    free_ubi_create_attestation_key_out(out);
}
void test_ubi_load_attestation_key(void) {
    // Step 1: Create an attestation key
    struct ubi_create_attestation_key_in create_in;
    create_in.curve_type = BNP_256; // Set a valid curve type for the test
    struct ubi_buffer policy;
    uint8_t policy_data[] = {0x01, 0x02, 0x03, 0x04}; // Example policy data
    policy.buffer = policy_data;
    policy.buffer_len = sizeof(policy_data);
    create_in.policy = &policy;

    struct ubi_create_attestation_key_out *create_out = NULL;

    int create_result = ubi_create_attestation_key(&create_in, &create_out);

    // Assertions for the create function
    assert(create_result == UBI_SUCCESS);
    assert(create_out->seed != NULL);
    assert(create_out->seed->buffer_len == SHA256_DIGEST_LENGTH);
    assert(create_out->hash_private_key != NULL);
    assert(create_out->hash_private_key->buffer_len == SHA256_DIGEST_LENGTH);
    assert(create_out->public_key != NULL);
    assert(create_out->public_key->buffer_len == 65); // Mocked public key length
    assert(create_out->name != NULL);
    assert(create_out->name->buffer_len == KEY_NAME_LENGTH);

    // Check if the first two bytes of name are as expected
    assert(create_out->name->buffer[0] == RH_NULL);
    assert(create_out->name->buffer[1] == ALG_SHA256);

    print_ubi_create_attestation_key_out(create_out);

    // Step 2: Load the attestation key using the previously created key
    struct ubi_load_attestation_key_in load_in;
    load_in.policy = &policy;
    load_in.seed = create_out->seed;
    load_in.hash_private_key = create_out->hash_private_key; // Use the hash of the private key from creation
    struct ubi_load_attestation_key_out *load_out = NULL;

    int load_result = ubi_load_attestation_key(&load_in, &load_out);

    // Assertions for the load function
    assert(load_result == UBI_SUCCESS);
    assert(load_out->private_key != NULL);
    assert(load_out->private_key->buffer_len == SHA256_DIGEST_LENGTH);

    // Step 3: Cleanup all allocated memory
    free(create_out->seed->buffer);
    free(create_out->seed);
    free(create_out->hash_private_key->buffer);
    free(create_out->hash_private_key);
    free(create_out->name->buffer);
    free(create_out->name);
    free(create_out->public_key->buffer);
    free(create_out->public_key);
    free(create_out);

    // Free the loaded private key
    free_ubi_load_attestation_key_out(load_out);
}
void test_ubi_create_migratable_key(void);

void test_ubi_create_migratable_key(void) {
    int ret = UBI_SUCCESS;

    // Input structure
    struct ubi_create_migratable_key_in in;
    in.curve_type = BNP_256; // Set a valid curve type for the test

    // Example policy data
    struct ubi_buffer policy;
    uint8_t policy_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    policy.buffer = policy_data;
    policy.buffer_len = sizeof(policy_data);
    in.policy = &policy;

    // Output structure
    struct ubi_create_migratable_key_out *out = NULL;
    // memset(&out, 0, sizeof(out)); // Ensure the output structure is initialized to 0

    // Call the function to test
    ret = ubi_create_migratable_key(&in, &out);

    // Assertions
    assert(ret == UBI_SUCCESS); // Ensure function succeeded
    assert((*out).encrypted_private_key != NULL);
    assert((*out).encrypted_private_key->buffer_len > 0);
    assert((*out).encrypted_private_key->buffer != NULL);

    assert((*out).hash_private_key != NULL);
    assert((*out).hash_private_key->buffer_len == SHA256_DIGEST_LENGTH);
    assert((*out).hash_private_key->buffer != NULL);

    assert((*out).name != NULL);
    assert((*out).name->buffer_len == KEY_NAME_LENGTH);
    assert((*out).name->buffer != NULL);
    assert((*out).name->buffer[0] == RH_NULL); // Check the first byte of the name
    assert((*out).name->buffer[1] == ALG_SHA256); // Check the second byte of the name

    assert((*out).public_key != NULL);
    assert((*out).public_key->buffer_len > 0);
    assert((*out).public_key->buffer != NULL);

    // Verify the IV was generated
    int iv_is_not_zero = 0;
    for (int i = 0; i < IV_SIZE; i++) {
        if ((*out).iv[i] != 0) {
            iv_is_not_zero = 1;
            break;
        }
    }
    assert(iv_is_not_zero); // Ensure IV is not all zeros

    // Cleanup
    if ((*out).encrypted_private_key != NULL) {
        free((*out).encrypted_private_key->buffer);
        free((*out).encrypted_private_key);
    }

    if ((*out).hash_private_key != NULL) {
        free((*out).hash_private_key->buffer);
        free((*out).hash_private_key);
    }

    if ((*out).name != NULL) {
        free((*out).name->buffer);
        free((*out).name);
    }

    if ((*out).public_key != NULL) {
        free((*out).public_key->buffer);
        free((*out).public_key);
    }
    free(out);

    printf("test_ubi_create_migratable_key passed successfully!\n");
}

void test_ubi_load_migratable_key(void);

void test_ubi_load_migratable_key(void) {
    int ret = UBI_SUCCESS;

    // Step 1: Create a migratable key using ubi_create_migratable_key

    // Input structure for key creation
    struct ubi_create_migratable_key_in create_in;
    create_in.curve_type = BNP_256; // Set a valid curve type for the test

    // Example policy data for creation
    struct ubi_buffer policy;
    uint8_t policy_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    policy.buffer = policy_data;
    policy.buffer_len = sizeof(policy_data);
    create_in.policy = &policy;

    // Output structure for key creation
    struct ubi_create_migratable_key_out *create_out = NULL;
    memset(&create_out, 0, sizeof(create_out)); // Ensure the output structure is initialized to 0

    // Call the function to create the key
    ret = ubi_create_migratable_key(&create_in, &create_out);
    print_ubi_create_migratable_key_in(&create_in);
    print_ubi_create_migratable_key_out(create_out);

    // Assertions for key creation
    assert(ret == UBI_SUCCESS); // Ensure function succeeded
    assert(create_out->encrypted_private_key != NULL);
    assert(create_out->encrypted_private_key->buffer_len > 0);
    assert(create_out->encrypted_private_key->buffer != NULL);

    assert(create_out->hash_private_key != NULL);
    assert(create_out->hash_private_key->buffer_len == SHA256_DIGEST_LENGTH);
    assert(create_out->hash_private_key->buffer != NULL);

    assert(create_out->name != NULL);
    assert(create_out->name->buffer_len == KEY_NAME_LENGTH);
    assert(create_out->name->buffer != NULL);

    assert(create_out->public_key != NULL);
    assert(create_out->public_key->buffer_len > 0);
    assert(create_out->public_key->buffer != NULL);

    // Step 2: Load the migratable key using ubi_load_migratable_key

    // Input structure for key loading
    struct ubi_load_migratable_key_in load_in;
    load_in.encrypted_private_key = create_out->encrypted_private_key;
    load_in.hash_private_key = create_out->hash_private_key;
    load_in.policy = create_in.policy;
    memcpy(load_in.iv, create_out->iv, IV_SIZE);

    // // Output structure for key loading
    struct ubi_load_migratable_key_out *load_out = NULL;

    // Call the function to load the key
    ret = ubi_load_migratable_key(&load_in, &load_out);
    print_ubi_load_migratable_key_in(&load_in);
    printf("%d\n", ret);

    // Assertions for key loading
    assert(ret == UBI_SUCCESS); // Ensure function succeeded
    assert(load_out->private_key != NULL);
    assert(load_out->private_key->buffer_len == SHA256_DIGEST_LENGTH); // Assuming private key length is SHA256_DIGEST_LENGTH
    assert(load_out->private_key->buffer != NULL);


    free_ubi_create_migratable_key_out(create_out); 
    free_ubi_load_migratable_key_out(load_out);

    printf("test_ubi_load_migratable_key passed successfully!\n");
}



// int main(void) {
//     // Run the test
//     test_ubi_compute_public_key();
//     test_ubi_create_attestation_key();
//     test_ubi_load_attestation_key();
//     test_ubi_load_migratable_key();
//     test_ubi_create_migratable_key();
//     printf("Test passed successfully!\n");
//     return 0;
// }

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No arguments: use hardcoded values
        printf("Using default hardcoded policy and curve.\n");
        uint8_t default_policy[] = {0x01, 0x02, 0x03, 0x04};
        test_ubi_create_attestation_key(default_policy, sizeof(default_policy), BNP_256);
    } else if (argc == 3) {
        // Argument mode: expects a hex policy and a curve type
        char *policy_hex = argv[1];
        int curve_type = atoi(argv[2]);

        size_t policy_len = strlen(policy_hex) / 2;
        uint8_t *policy_data = malloc(policy_len);
        if (!policy_data) {
            perror("malloc");
            return 1;
        }

        for (size_t i = 0; i < policy_len; i++) {
            sscanf(&policy_hex[i * 2], "%2hhx", &policy_data[i]);
        }

        printf("Using provided policy and curve.\n");
        test_ubi_create_attestation_key(policy_data, policy_len, curve_type);
        free(policy_data);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s                 # Run with hardcoded data\n", argv[0]);
        fprintf(stderr, "  %s <policy_hex> <curve_type>  # Run with arguments\n", argv[0]);
        return 1;
    }

    test_ubi_compute_public_key();
    test_ubi_load_attestation_key();
    test_ubi_load_migratable_key();
    test_ubi_create_migratable_key();
    printf("Test passed successfully!\n");
    return 0;
}