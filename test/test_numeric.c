#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ubi_crypt/numeric.h>

void print_hex(const char *label, const unsigned char *data, size_t len);

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_ubi_mod(void);

void test_ubi_mod(void){
    int ret;

    // Example input: 1234567890 mod 9876543210
    uint8_t input_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x02, 0x96, 0x49, 0xF6, 0x64, 0x5A
    };
    uint8_t mod_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x1A
    };

    ubi_buffer input = {input_data, sizeof(input_data)};
    ubi_buffer mod = {mod_data, sizeof(mod_data)};

    ubi_mod_in in = {&mod, &input};
    ubi_mod_out *out = NULL;

    // Call the function
    ret = ubi_mod(&in, &out);

    // Check for errors
    if (ret != 0) {
        printf("ubi_mod failed with error code %d\n", ret);
    }

    // Print the results
    print_hex("Input", input.buffer, input.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", (*out).output->buffer, (*out).output->buffer_len);
    // Free allocated output buffer
    free((*out).output->buffer);
    free((*out).output);
    free(out);
}

void test_ubi_mod_add(void);

void test_ubi_mod_add(void){
    int ret;

    // Example input: 1234567890 + 9876543210 mod 9876543210
    uint8_t adder_data1[] = {
        0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x02, 0x96, 0x49, 0xF6, 0x64, 0x5A
    };
    uint8_t adder_data2[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x1A
    };
    uint8_t mod_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x3A
    };

    ubi_buffer adder1 = {adder_data1, sizeof(adder_data1)};
    ubi_buffer adder2 = {adder_data2, sizeof(adder_data2)};
    ubi_buffer mod = {mod_data, sizeof(mod_data)};

    ubi_buffer *adders[] = {&adder1, &adder2};

    ubi_mod_add_in in = {&mod, adders, 2};
    ubi_mod_add_out *out = NULL;

    // Call the function
    ret = ubi_mod_add(&in, &out);

    // Check for errors
    if (ret != 0) {
        printf("ubi_mod_add failed with error code %d\n", ret);
    }

    // Print the results
    print_hex("Adder 1", adder1.buffer, adder1.buffer_len);
    print_hex("Adder 2", adder2.buffer, adder2.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", (*out).output->buffer, (*out).output->buffer_len);
    // Free allocated output buffer
    free_ubi_mod_add_out(out);
}


void test_ubi_mod_mul(void);

void test_ubi_mod_mul(void){
    int ret;

    // Example input: 1234567890 + 9876543210 mod 9876543210
    uint8_t mul_data1[] = {
        0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x02, 0x96, 0x49, 0xF6, 0x64, 0x5A
    };
    uint8_t mul_data2[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x1A
    };
    uint8_t mod_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x3A
    };

    ubi_buffer mul1 = {mul_data1, sizeof(mul_data1)};
    ubi_buffer mul2 = {mul_data2, sizeof(mul_data2)};
    ubi_buffer mod = {mod_data, sizeof(mod_data)};

    ubi_buffer *multers[] = {&mul1, &mul2};

    ubi_mod_mul_in in = {&mod, multers, 2};
    ubi_mod_mul_out *out = NULL;

    // Call the function
    ret = ubi_mod_mul(&in, &out);

    // Check for errors
    if (ret != 0) {
        printf("ubi_mod_mul failed with error code %d\n", ret);
    }

    // Print the results
    print_hex("mult 1", mul1.buffer, mul1.buffer_len);
    print_hex("mult 2", mul2.buffer, mul2.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", (*out).output->buffer, (*out).output->buffer_len);
    // Free allocated output buffer
    free_ubi_mod_mul_out(out);
}

void test_ubi_mod_inv(void);

void test_ubi_mod_inv(void){
    int ret;

    uint8_t input_data[] = {
    0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x02, 0x96, 0x1B, 0xF6, 0x64, 0x5A
    };
    uint8_t mod_data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71,
                                0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C,
                                0xD1, 0x0B, 0x50, 0x0D};

    ubi_buffer input = {input_data, sizeof(input_data)};
    ubi_buffer mod = {mod_data, sizeof(mod_data)};

    ubi_mod_inv_in in = {&mod, &input};
    ubi_mod_inv_out *out = NULL;

    // Call the function
    ret = ubi_mod_inverse(&in, &out);

    // Check for errors
    if (ret != 0) {
        printf("ubi_mod failed with error code %d\n", ret);
    }

    // Print the results
    print_hex("Input", input.buffer, input.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", (*out).output->buffer, (*out).output->buffer_len);
    // Free allocated output buffer
    free_ubi_mod_inv_out(out);
}

void test_ubi_sub_mod(void);

void test_ubi_sub_mod(void){
    int ret;

    // Example input: 1234567890 - 9876543210 mod 9876543210
    uint8_t src_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x02, 0x96, 0x49, 0xF6, 0x64, 0x5A
    };
    uint8_t sub_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x1A
    };
    uint8_t mod_data[] = {
        0x00, 0x00, 0x00, 0x00, 0x92, 0x7C, 0xC0, 0x09, 0x1E, 0xA2, 0x6F, 0x3A
    };

    ubi_buffer src = {src_data, sizeof(src_data)};
    ubi_buffer sub = {sub_data, sizeof(sub_data)};
    ubi_buffer mod = {mod_data, sizeof(mod_data)};

    ubi_mod_sub_in in = {&mod, &src, &sub};
    ubi_mod_sub_out *out = NULL;

    // Call the function
    ret = ubi_mod_sub(&in, &out);

    // Check for errors
    if (ret != 0) {
        printf("ubi_mod_sub failed with error code %d\n", ret);
    }

    // Print the results
    print_hex("Source", src.buffer, src.buffer_len);
    print_hex("Subtract", sub.buffer, sub.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", (*out).output->buffer, (*out).output->buffer_len);
    // Free allocated output buffer
    free_ubi_mod_sub_out(out);
}

int main(void) {
   
   test_ubi_mod();  

   test_ubi_mod_add();  

   test_ubi_mod_mul();

   test_ubi_mod_inv();

   test_ubi_sub_mod();
    return 0;
}
