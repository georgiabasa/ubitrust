#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/numeric.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>

#define MOD_ORDER_SIZE 16
#define RANDOM_BYTES_SIZE 16

void test_ubi_random_bytes_mod(void);

void test_ubi_random_bytes_mod(void) {
    struct ubi_random_bytes_mod_in in;
    struct ubi_random_bytes_mod_out *out = NULL;
    int ret;

    // Initialize mod_order buffer
    struct ubi_buffer mod_order;
    mod_order.buffer = malloc(MOD_ORDER_SIZE);
    mod_order.buffer_len = MOD_ORDER_SIZE;
    for (int i = 0; i < MOD_ORDER_SIZE; i++) {
        mod_order.buffer[i] = (uint8_t)i + 1;
    }

    // Set input parameters
    in.bytes_num = RANDOM_BYTES_SIZE;
    in.mod_order = &mod_order;

    // Call the function
    ret = ubi_random_bytes_mod(&in, &out);

    // Check the return value
    if (ret != UBI_SUCCESS) {
        printf("ubi_random_bytes_mod failed with error code: %d\n", ret);
    } else {
        printf("ubi_random_bytes_mod succeeded\n");

        // Print the generated random bytes mod in hexadecimal format
        printf("Generated random bytes mod: ");
        for (size_t i = 0; i < (*out).random_bytes_mod->buffer_len; i++) {
            printf("%02x", (*out).random_bytes_mod->buffer[i]);
        }
        printf("\n");
    }

    // Free allocated memory
    free_ubi_random_bytes_mod_out(out);
    free(mod_order.buffer);
}




int main(void) {

    test_ubi_random_bytes_mod();


    return 0;
}
