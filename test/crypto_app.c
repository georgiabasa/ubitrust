#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ecp.h>
#include <ubi_crypt/rand.h>
#include <ubi_crypt/ec.h>
#include <ubi_common/errors.h>
#include <ubi_common/macros.h>
#include <ubi_common/structs.h>


#define RANDOM_BYTES_SIZE 32  // for 256-bit curve
#define MAX_ORDER_BYTES 32     // Maximum bytes for order of curve (BNP256)

struct scalar {
    uint8_t *buffer;
    size_t length;
};

struct group_generator {
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

struct group_generator generate_group_generator(void) {
    struct group_generator result = {NULL, 0};

    struct ubi_compute_group_generator_in gen_in = { .curve_type = BNP_256 };
    struct ubi_compute_group_generator_out *gen_out = NULL;

    if (ubi_compute_group_generator(&gen_in, &gen_out) != UBI_SUCCESS || !gen_out || !gen_out->generator) {
        return result;
    }

    result.length = gen_out->generator->buffer_len;
    result.buffer = malloc(result.length);
    if (result.buffer) {
        memcpy(result.buffer, gen_out->generator->buffer, result.length);
    }

    free_ubi_compute_group_generator_out(gen_out);
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

    struct scalar *scalars = malloc((size_t)n * sizeof(struct scalar));
    struct group_generator *generators = malloc((size_t)n * sizeof(struct group_generator));
    if (!scalars || !generators) {
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

        // Generate n group generators
        generators[i] = generate_group_generator();
        if (!generators[i].buffer) {
            printf("Failed to generate group generator %d\n", i);
        } else {
            printf("Group generator G[%d]: ", i);
            for (size_t j = 0; j < generators[i].length; j++) {
                printf("%02x", generators[i].buffer[j]);
            }
            printf("\n");
        }
    }

    //free all buffers
    for (int i = 0; i < n; ++i) {
        free(scalars[i].buffer);
        free(generators[i].buffer);
    }
    free(scalars);
    free(generators);

    return 0;
}