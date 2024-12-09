#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ubi_crypt/hmac.h>
#include <ubi_common/structs.h>

void print_hex(const char *label, const uint8_t *data, size_t len);

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    int ret;

    const char *test_messages[50] = {
        "Hello, World!", "Test message 1", "Test message 2", "Test message 3",
        "Test message 4", "Test message 5", "Test message 6", "Test message 7",
        "Test message 8", "Test message 9", "Test message 10", "Test message 11",
        "Test message 12", "Test message 13", "Test message 14", "Test message 15",
        "Test message 16", "Test message 17", "Test message 18", "Test message 19",
        "Test message 20", "Test message 21", "Test message 22", "Test message 23",
        "Test message 24", "Test message 25", "Test message 26", "Test message 27",
        "Test message 28", "Test message 29", "Test message 30", "Test message 31",
        "Test message 32", "Test message 33", "Test message 34", "Test message 35",
        "Test message 36", "Test message 37", "Test message 38", "Test message 39",
        "Test message 40", "Test message 41", "Test message 42", "Test message 43",
        "Test message 44", "Test message 45", "Test message 46", "Test message 47",
        "Test message 48", "Test message 49"
    };

    // Convert messages to ubi_message structures
    ubi_buffer messages[50];
    for (int i = 0; i < 50; i++) {
        messages[i].buffer = (uint8_t *)test_messages[i];
        messages[i].buffer_len = strlen(test_messages[i]);
    }
    

    // Test data: key and data to be hashed
    uint8_t key_data[] = { 0x4b, 0x65, 0x79, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65 }; // "Key_example"
    // uint8_t data[] = { 0x44, 0x61, 0x74, 0x61, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65 }; // "Data_example"
    struct ubi_buffer key = {
        .buffer = key_data,
        .buffer_len = sizeof(key_data)
    };
    struct ubi_hmac_sha256_in in = {
        .messages = messages,
        .messages_len = 50,
        &key};
    struct ubi_hmac_sha256_out *out = NULL;

    // Call the function
    ret = ubi_hmac_sha256(&in, &out);
    
    // Check for errors
    if (ret != 0) {
        printf("ubi_hmac_sha256 failed with error code %d\n", ret);
        return ret;
    }

    // Print the results
    print_hex("HMAC Digest", (*out).hmac_digest->buffer, (*out).hmac_digest->buffer_len);

    // Free the allocated memory for HMAC digest
    free_ubi_hmac_sha256_out(out);

    return 0;
}
