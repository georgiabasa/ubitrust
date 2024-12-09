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

int main(void) {
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
        return ret;
    }

    // Print the results
    print_hex("Input", input.buffer, input.buffer_len);
    print_hex("Modulus", mod.buffer, mod.buffer_len);
    print_hex("Output", out->output->buffer, out->output->buffer_len);
    // Free allocated output buffer
    free((*out).output->buffer);
    free((*out).output);
    free(out);

    return 0;
}
