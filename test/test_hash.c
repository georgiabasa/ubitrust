#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ubi_crypt/hash.h>
#include <ubi_common/structs.h>

int main(void) {
    // Array of test messages
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

    // Create ubi_sha256_in structure
    ubi_sha_in in = {
        .messages = messages,
        .messages_len = 50
    };

    // Prepare output structure
    ubi_sha_out *out = NULL;

    // Call the sha256 function
    int result = ubi_sha256(&in, &out);

    if (result == 0) {
        printf("SHA256 Digest: ");
        for (size_t i = 0; i < (*out).digest->buffer_len; i++) {
            printf("%02x", (*out).digest->buffer[i]);
        }
        printf("\nTest Passed\n");
    } else {
        printf("Test Failed\n");
    }
    free_ubi_sha_out(out);
    return result;
}
