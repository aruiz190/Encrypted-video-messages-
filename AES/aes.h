#include <stdint.h>
#include <string.h>
#include "aes.h"

void aes_ctr_encrypt(const uint8_t *input, uint8_t *output, uint32_t length, const uint8_t *key, const uint8_t *iv) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(output, input, length);
    AES_CTR_xcrypt_buffer(&ctx, output, length);
}
