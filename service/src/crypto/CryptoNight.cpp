#include "CryptoNight_x86.h"

#include <sys/mman.h>

extern "C"
void cryptonight_monerov7(const unsigned char *d, size_t n, unsigned char *md) {
    static cryptonight_ctx *ctx;
    if (ctx == NULL) {
        ctx = static_cast<cryptonight_ctx *>(calloc(1, sizeof(cryptonight_ctx)));
        constexpr size_t MEM = xmrig::cn_select_memory<xmrig::CRYPTONIGHT>();
        ctx->memory = static_cast<uint8_t *>(mmap(NULL, MEM, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    }
    cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_1>(d, n, md, &ctx);
}

extern "C"
void cryptonight(const unsigned char *d, size_t n, unsigned char *md) {
    static cryptonight_ctx *ctx;
    if (ctx == NULL) {
        ctx = static_cast<cryptonight_ctx *>(calloc(1, sizeof(cryptonight_ctx)));
        constexpr size_t MEM = xmrig::cn_select_memory<xmrig::CRYPTONIGHT>();
        ctx->memory = static_cast<uint8_t *>(mmap(NULL, MEM, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    }
    cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_0>(d, n, md, &ctx);
}
