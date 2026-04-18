#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../crates/acp-ffi/include/acp.h"

int main() {
    printf("ACP C Example - Basic Encryption\n\n");

    // Generate a key
    printf("Generating key...\n");
    AcpKey* key = NULL;
    AcpErrorCode result = acp_key_generate(ACP_ALGORITHM_AES_256_GCM, &key);
    if (result != ACP_OK) {
        fprintf(stderr, "Key generation failed: %s\n", acp_error_message(result));
        return 1;
    }
    printf("Key generated successfully\n\n");

    // Create a session
    printf("Creating session...\n");
    AcpSession* session = NULL;
    result = acp_session_new(key, "c-example-session", &session);
    if (result != ACP_OK) {
        fprintf(stderr, "Session creation failed: %s\n", acp_error_message(result));
        acp_key_free(key);
        return 1;
    }
    printf("Session created successfully\n\n");

    // Encrypt data
    const char* plaintext = "Hello from C!";
    size_t plaintext_len = strlen(plaintext);

    printf("Plaintext: %s\n", plaintext);
    printf("Encrypting...\n");

    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    result = acp_session_encrypt(
        session,
        (const uint8_t*)plaintext,
        plaintext_len,
        &ciphertext,
        &ciphertext_len
    );

    if (result != ACP_OK) {
        fprintf(stderr, "Encryption failed: %s\n", acp_error_message(result));
        acp_session_free(session);
        acp_key_free(key);
        return 1;
    }
    printf("Ciphertext: %zu bytes\n\n", ciphertext_len);

    // Decrypt data
    printf("Decrypting...\n");
    uint8_t* decrypted = NULL;
    size_t decrypted_len = 0;
    result = acp_session_decrypt(
        session,
        ciphertext,
        ciphertext_len,
        &decrypted,
        &decrypted_len
    );

    if (result != ACP_OK) {
        fprintf(stderr, "Decryption failed: %s\n", acp_error_message(result));
        acp_free_buffer(ciphertext);
        acp_session_free(session);
        acp_key_free(key);
        return 1;
    }

    // Verify
    printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);

    if (decrypted_len == plaintext_len &&
        memcmp(decrypted, plaintext, plaintext_len) == 0) {
        printf("\n✓ Encryption/decryption successful!\n");
    } else {
        fprintf(stderr, "\n✗ Verification failed!\n");
    }

    // Cleanup
    acp_free_buffer(decrypted);
    acp_free_buffer(ciphertext);
    acp_session_free(session);
    acp_key_free(key);

    printf("\nACP version: %s\n", acp_version());

    return 0;
}
