#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/ec.h>
#include <ubi_common/errors.h>

#define RANDOM_BYTES_SIZE 32  // for 256-bit curve
#define MAX_ORDER_BYTES 32     // Maximum bytes for order of curve (BNP256)

struct scalar {
    uint8_t *buffer;
    size_t length;
};

struct scalar generate_scalar_modulo_q(mbedtls_ecp_group *grp) {
    struct scalar result = {NULL, 0};

    uint8_t order_buf[MAX_ORDER_BYTES];
    size_t order_len = mbedtls_mpi_size(&grp->N);
    mbedtls_mpi_write_binary(&grp->N, order_buf, order_len);

    struct ubi_buffer mod_order = {
        .buffer = order_buf,
        .buffer_len = order_len
    };

    struct ubi_random_bytes_mod_in mod_in = {
        .bytes_num = RANDOM_BYTES_SIZE,
        .mod_order = &mod_order
    };

    struct ubi_random_bytes_mod_out *mod_out = NULL;
    if (ubi_random_bytes_mod(&mod_in, &mod_out) != UBI_SUCCESS) {
        return result;
    }

    result.length = mod_out->random_bytes_mod->buffer_len;
    result.buffer = malloc(result.length);
    if (result.buffer) {
        memcpy(result.buffer, mod_out->random_bytes_mod->buffer, result.length);
    }

    free_ubi_random_bytes_mod_out(mod_out);
    return result;
}

int main() {
    int n;
    mbedtls_ecp_group *grp = NULL;

    // Step 1: Get input integer n
    do {
        printf("Enter a positive integer: ");
        scanf("%d", &n);
        if (n <= 0) {
            printf("Invalid input. Please enter a positive integer.\n");
        }
    } while (n <= 0);

    // Step 2: Initialize EC group (BNP256)
    if (ubi_get_ec_group_bnp256(&grp) != UBI_SUCCESS) {
        printf("Failed to get EC group\n");
        return -1;
    }

    struct scalar *scalars = malloc(n * sizeof(struct scalar));
    if (!scalars) {
        printf("Memory allocation failed\n");
        return -1;
    }

    for (int i = 0; i < n; ++i) {

        // Generate n random scalars mod q
        scalars[i] = generate_scalar_modulo_q(grp);
        if (!scalars[i].buffer) {
            printf("Failed to generate scalar %d\n", i);
        } else {
            printf("Scalar r[%d]: ", i);
            for (size_t j = 0; j < scalars[i].length; j++) {
                printf("%02x", scalars[i].buffer[j]);
            }
            printf("\n");
        }
    }

    for (int i = 0; i < n; ++i) {
        free(scalars[i].buffer);
    }
    free(scalars);

    return 0;
}