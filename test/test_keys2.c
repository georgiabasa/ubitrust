#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <ubi_crypt/keys2.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


int main(void) {
    struct ubi_create_key2_in in;
    struct ubi_create_key2_out *out = NULL;
    int ret = UBI_SUCCESS;

    in.curve_type = BNP_256;

    ret = ubi_create_key2(&in, &out);

    if (ret != UBI_SUCCESS) {
        printf("ubi_create_key2 failed with error code: %d\n", ret);
    } else {
        printf("ubi_create_key2 succeeded\n");

        // Print the generated private key in hexadecimal format
        printf("Generated private key: ");
        for (size_t i = 0; i < (*out).private_key->buffer_len; i++) {
            printf("%02x", (*out).private_key->buffer[i]);
        }
        printf("\n");

        // Print the generated public key in hexadecimal format
        printf("Generated public key: ");
        for (size_t i = 0; i < (*out).public_key->buffer_len; i++) {
            printf("%02x", (*out).public_key->buffer[i]);
        }
        printf("\n");

        // Print the generated generator in hexadecimal format
        printf("Generated generator: ");
        for (size_t i = 0; i < (*out).generator->buffer_len; i++) {
            printf("%02x", (*out).generator->buffer[i]);
        }
        printf("\n");
    }

    free_ubi_create_key2_out(out);

    return 0;
}