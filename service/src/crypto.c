#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include <crypto/CryptoNight.h>

void ooo_hash(const unsigned char *d, size_t n, unsigned char *md) {
    unsigned char tmp[SHA256_DIGEST_LENGTH];
    cryptonight(d, n, (uint8_t *)&tmp);
    SHA256((const uint8_t *)&tmp, SHA256_DIGEST_LENGTH, md);
}
