#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <ubi_crypt/kdf.h>
#include <ubi_common/structs.h>

void print_buffer(uint8_t *buffer, size_t len);

void print_buffer(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

int main(void) {
    // Prepare test input data
    uint8_t seed_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t label_data[] = {0x4C, 0x61, 0x62, 0x65, 0x6C};
    uint8_t context_u_data[] = {0x55, 0x73, 0x65, 0x72};
    uint8_t context_v_data[] = {0x56, 0x65, 0x6E, 0x64, 0x6F, 0x72};

    struct ubi_buffer seed = {seed_data, sizeof(seed_data)};
    struct ubi_buffer label = {label_data, sizeof(label_data)};
    struct ubi_buffer context_u = {context_u_data, sizeof(context_u_data)};
    struct ubi_buffer context_v = {context_v_data, sizeof(context_v_data)};

    size_t key_len_bits = 256;  // Desired key length in bits

    struct ubi_kdf_in kdf_input = {&seed, &label, &context_u, &context_v, key_len_bits};
    
    struct ubi_kdf_out *kdf_output = NULL;

    // Call the kdf_sha256 function
    ubi_kdf_sha256(&kdf_input, &kdf_output);

    // Print the generated key
    printf("Generated key: ");
    print_buffer(kdf_output->key->buffer, kdf_output->key->buffer_len);

    printf("Test passed!\n");
    free_ubi_kdf_out(kdf_output);
    return 0;
}
