#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h>
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

void test_ubi_constant_time_rng(void);

void test_ubi_constant_time_rng(void) {
    struct ubi_constant_time_rng_in in;
    struct ubi_constant_time_rng_out out;
    int ret;

    // Set input parameters
    in.i = 50;
    in.k = 6;
    in.N = 10;

    // Call the function
    ret = ubi_constant_time_rng(&in, &out);

    // Check the return value
    if (ret != UBI_SUCCESS) {
        printf("ubi_constant_time_rng failed with error code: %d\n", ret);
    } else {
        printf("ubi_constant_time_rng succeeded\n");

        // Print the generated random value
        printf("Generated random value: %d\n", out.random_value);
    }
}

double get_cpu_frequency(void);

double get_cpu_frequency(void) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        perror("Failed to read /proc/cpuinfo");
        return -1.0;
    }

    char buffer[1024];
    double cpu_mhz = 0.0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (sscanf(buffer, "cpu MHz\t: %lf", &cpu_mhz) == 1) {
            fclose(fp);
            return cpu_mhz * 1e6; // Convert MHz to Hz
        }
    }

    fclose(fp);
    return -1.0; // Failed to retrieve frequency
}

void benchmark_ubi_constant_time_rng(void);

void benchmark_ubi_constant_time_rng(void) {
    uint64_t start_cycles, end_cycles;
    double elapsed_cycles;

    // Record the start cycle count
    start_cycles = __rdtsc();

    // Run the test function
    test_ubi_constant_time_rng();

    // Record the end cycle count
    end_cycles = __rdtsc();
    double cpu_frequency = get_cpu_frequency();

    // Calculate the elapsed cycles
    elapsed_cycles = (double)(end_cycles - start_cycles);
    double elapsed_time = (double)elapsed_cycles / cpu_frequency;

    printf("CPU cycles elapsed: %lu\n", elapsed_cycles);
    printf("Elapsed time: %.9f seconds\n", elapsed_time);
}


int main(void) {
    unsigned char output[RANDOM_BYTES_SIZE];
    int ret = 0;

    // Generate random bytes
    ret = ubi_random_bytes(NULL, output, RANDOM_BYTES_SIZE);

    if (ret != 0) {
        printf("Failed to generate random bytes\n");
        return 1;
    }

    // Print the generated random bytes in hexadecimal format
    printf("Generated random bytes: ");
    for (int i = 0; i < RANDOM_BYTES_SIZE; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    test_ubi_random_bytes_mod();

    test_ubi_constant_time_rng();
    benchmark_ubi_constant_time_rng();

    return 0;
}
