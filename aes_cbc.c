#include <tomcrypt.h>

unsigned char key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

unsigned char iv[]  = {
    0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72,
    0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21
};

int aes_cbc_encrypt(unsigned char plain_text[], unsigned char chiper_text[], unsigned long ciphertext_length) {
    symmetric_CBC cbc;
    int err;

    err = register_cipher(&aes_desc);
    if (err != CRYPT_OK) {
        printf("Error registering cipher: %s\n", error_to_string(err));
        return 1;
    }

    int keysize = sizeof(key);
    err = aes_keysize(&keysize);
    if (err != CRYPT_OK) {
        printf("Error aes keysize: %s\n", error_to_string(err));
        return 1;
    }

    symmetric_key skey;
    err = aes_setup(key, sizeof(key), 0, &skey);
    if (err != CRYPT_OK) {
        printf("Error aes setup: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_start(find_cipher("aes"), iv, key, sizeof(key), 0, &cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc start: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_encrypt(plain_text, chiper_text, ciphertext_length, &cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc encrypt: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_done(&cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc done: %s\n", error_to_string(err));
        return 1;
    }

    err = unregister_cipher(&aes_desc);
    if (err != CRYPT_OK) {
        printf("Error unregister cipher: %s\n", error_to_string(err));
        return 1;
    }

    return 0;
}

int aes_cbc_decrypt(unsigned char chiper_text[], unsigned char plain_text[], unsigned long chipertext_length) {
    symmetric_CBC cbc;
    int err;

    err = register_cipher(&aes_desc);
    if (err != CRYPT_OK) {
        printf("Error registering cipher: %s\n", error_to_string(err));
        return 1;
    }

    int keysize = sizeof(key);
    err = aes_keysize(&keysize);
    if (err != CRYPT_OK) {
        printf("Error aes keysize: %s\n", error_to_string(err));
        return 1;
    }

    symmetric_key skey;
    err = aes_setup(key, sizeof(key), 0, &skey);
    if (err != CRYPT_OK) {
        printf("Error aes setup: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_start(find_cipher("aes"), iv, key, sizeof(key), 0, &cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc start: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_decrypt(chiper_text, plain_text, chipertext_length, &cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc decrypt: %s\n", error_to_string(err));
        return 1;
    }

    err = cbc_done(&cbc);
    if (err != CRYPT_OK) {
        printf("Error cbc done: %s\n", error_to_string(err));
        return 1;
    }

    err = unregister_cipher(&aes_desc);
    if (err != CRYPT_OK) {
        printf("Error unregister cipher: %s\n", error_to_string(err));
        return 1;
    }

    return 0;
}

int main() {
    unsigned char text[] = { 'H', 'e', 'l', 'l', 'o', '!', '\0' };
    unsigned char encrypt[256];
    unsigned char decrypt[256];
    unsigned long len = 256;

    printf("\nAES-256bit CBC mode\n");

    int err = aes_cbc_encrypt(text, encrypt, len);
    if (err != 0) return 1;

    printf("\nEncrypt:");
    for (int i = 0; i < (int)len; i++) printf("%02X", encrypt[i]);

    err = aes_cbc_decrypt(encrypt, decrypt, len);
    if (err != 0) return 1;

    printf("\n\nDecrypt:");
    for (int i = 0; i < (int)sizeof(text); i++) printf("%c", decrypt[i]);
    printf("\n");

    return 0;
}
