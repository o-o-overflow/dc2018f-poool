/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CRYPTONIGHT_X86_H__
#define __CRYPTONIGHT_X86_H__


#ifdef __GNUC__
#   include <x86intrin.h>
#else
#   include <intrin.h>
#   define __restrict__ __restrict
#endif


#include "keccak.h"
#include "CryptoNight.h"
#include "CryptoNight_constants.h"
#include "CryptoNight_monero.h"
#include "soft_aes.h"


extern "C"
{
#include "c_groestl.h"
#include "c_blake256.h"
#include "c_jh.h"
#include "c_skein.h"
}


static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};



#if defined(__x86_64__) || defined(_M_AMD64)
#   define EXTRACT64(X) _mm_cvtsi128_si64(X)

#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif
#elif defined(__i386__) || defined(_M_IX86)
#   define HI32(X) \
    _mm_srli_si128((X), 4)


#   define EXTRACT64(X) \
    ((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
    ((uint64_t)(uint32_t)_mm_cvtsi128_si32(HI32(X)) << 32))

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}
#endif


// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = soft_aeskeygenassist<0x00>(*xout0);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}


template<bool SOFT_AES>
static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    if (SOFT_AES) {
        *x0 = soft_aesenc((uint32_t*)x0, key);
        *x1 = soft_aesenc((uint32_t*)x1, key);
        *x2 = soft_aesenc((uint32_t*)x2, key);
        *x3 = soft_aesenc((uint32_t*)x3, key);
        *x4 = soft_aesenc((uint32_t*)x4, key);
        *x5 = soft_aesenc((uint32_t*)x5, key);
        *x6 = soft_aesenc((uint32_t*)x6, key);
        *x7 = soft_aesenc((uint32_t*)x7, key);
    }
    else {
        *x0 = _mm_aesenc_si128(*x0, key);
        *x1 = _mm_aesenc_si128(*x1, key);
        *x2 = _mm_aesenc_si128(*x2, key);
        *x3 = _mm_aesenc_si128(*x3, key);
        *x4 = _mm_aesenc_si128(*x4, key);
        *x5 = _mm_aesenc_si128(*x5, key);
        *x6 = _mm_aesenc_si128(*x6, key);
        *x7 = _mm_aesenc_si128(*x7, key);
    }
}


inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);
    }
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
    {
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
            xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
            xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
            xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
            xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
            xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
            xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
            xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
            xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}


static inline __m128i aes_round_tweak_div(const __m128i &in, const __m128i &key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*) k, key);
    _mm_store_si128((__m128i*) x, _mm_xor_si128(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

    #define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
    #undef BYTE

    return _mm_load_si128((__m128i*)k);
}


template<int SHIFT>
static inline void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp)
{
    mem_out[0] = EXTRACT64(tmp);

    tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = EXTRACT64(tmp);

    uint8_t x = vh >> 24;
    static const uint16_t table = 0x7531;
    const uint8_t index = (((x >> SHIFT) & 6) | (x & 1)) << 1;
    vh ^= ((table >> index) & 0x3) << 28;

    mem_out[1] = vh;
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_MONERO    = xmrig::cn_is_monero<VARIANT>();

    if (IS_MONERO && size < 43) {
        memset(output, 0, 32);
        return;
    }

    xmrig::keccak(input, size, ctx[0]->state);

    VARIANT1_INIT(0)

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    uint64_t idx0 = al0;

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx;
        if (VARIANT == xmrig::VARIANT_TUBE || !SOFT_AES) {
            cx = _mm_load_si128((__m128i *) &l0[idx0 & MASK]);
        }

        if (VARIANT == xmrig::VARIANT_TUBE) {
            cx = aes_round_tweak_div(cx, _mm_set_epi64x(ah0, al0));
        }
        else if (SOFT_AES) {
            cx = soft_aesenc((uint32_t*)&l0[idx0 & MASK], _mm_set_epi64x(ah0, al0));
        }
        else {  
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));
        }

        if (IS_MONERO) {
            cryptonight_monero_tweak<VARIANT == xmrig::VARIANT_XTL ? 4 : 3>((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        } else {
            _mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        }

        idx0 = EXTRACT64(cx);
        bx0 = cx;

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch = ((uint64_t*) &l0[idx0 & MASK])[1];
        lo = __umul128(idx0, cl, &hi);

        al0 += hi;
        ah0 += lo;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;

        if (IS_MONERO) {
            if (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO) {
                ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0 ^ al0;
            }
            else {
                ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
            }
        }
        else {
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l0[idx0 & MASK])[0];
            int32_t d = ((int32_t*)&l0[idx0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx0 = d ^ q;
        }
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->memory, (__m128i*) ctx[0]->state);

    xmrig::keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_MONERO    = xmrig::cn_is_monero<VARIANT>();

    if (IS_MONERO && size < 43) {
        memset(output, 0, 64);
        return;
    }

    xmrig::keccak(input,        size, ctx[0]->state);
    xmrig::keccak(input + size, size, ctx[1]->state);

    VARIANT1_INIT(0);
    VARIANT1_INIT(1);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h0, (__m128i*) l0);
    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h1, (__m128i*) l1);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t ah1 = h1[1] ^ h1[5];

    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx0, cx1;
        if (VARIANT == xmrig::VARIANT_TUBE || !SOFT_AES) {
            cx0 = _mm_load_si128((__m128i *) &l0[idx0 & MASK]);
            cx1 = _mm_load_si128((__m128i *) &l1[idx1 & MASK]);
        }

        if (VARIANT == xmrig::VARIANT_TUBE) {
            cx0 = aes_round_tweak_div(cx0, _mm_set_epi64x(ah0, al0));
            cx1 = aes_round_tweak_div(cx1, _mm_set_epi64x(ah1, al1));
        }
        else if (SOFT_AES) {
            cx0 = soft_aesenc((uint32_t*)&l0[idx0 & MASK], _mm_set_epi64x(ah0, al0));
            cx1 = soft_aesenc((uint32_t*)&l1[idx1 & MASK], _mm_set_epi64x(ah1, al1));
        }
        else {
            cx0 = _mm_aesenc_si128(cx0, _mm_set_epi64x(ah0, al0));
            cx1 = _mm_aesenc_si128(cx1, _mm_set_epi64x(ah1, al1));
        }

        if (IS_MONERO) {
            cryptonight_monero_tweak<VARIANT == xmrig::VARIANT_XTL ? 4 : 3>((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx0));
            cryptonight_monero_tweak<VARIANT == xmrig::VARIANT_XTL ? 4 : 3>((uint64_t*)&l1[idx1 & MASK], _mm_xor_si128(bx1, cx1));
        } else {
            _mm_store_si128((__m128i *) &l0[idx0 & MASK], _mm_xor_si128(bx0, cx0));
            _mm_store_si128((__m128i *) &l1[idx1 & MASK], _mm_xor_si128(bx1, cx1));
        }

        idx0 = EXTRACT64(cx0);
        idx1 = EXTRACT64(cx1);

        bx0 = cx0;
        bx1 = cx1;

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch = ((uint64_t*) &l0[idx0 & MASK])[1];
        lo = __umul128(idx0, cl, &hi);

        al0 += hi;
        ah0 += lo;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;

        if (IS_MONERO) {
            if (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO) {
                ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0 ^ al0;
            }
            else {
                ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
            }
        }
        else {
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l0[idx0 & MASK])[0];
            int32_t d = ((int32_t*)&l0[idx0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx0 = d ^ q;
        }

        cl = ((uint64_t*) &l1[idx1 & MASK])[0];
        ch = ((uint64_t*) &l1[idx1 & MASK])[1];
        lo = __umul128(idx1, cl, &hi);

        al1 += hi;
        ah1 += lo;

        ((uint64_t*)&l1[idx1 & MASK])[0] = al1;

        if (IS_MONERO) {
            if (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO) {
                ((uint64_t*)&l1[idx1 & MASK])[1] = ah1 ^ tweak1_2_1 ^ al1;
            }
            else {
                ((uint64_t*)&l1[idx1 & MASK])[1] = ah1 ^ tweak1_2_1;
            }
        }
        else {
            ((uint64_t*)&l1[idx1 & MASK])[1] = ah1;
        }

        al1 ^= cl;
        ah1 ^= ch;
        idx1 = al1;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l1[idx1 & MASK])[0];
            int32_t d = ((int32_t*)&l1[idx1 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l1[idx1 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx1 = d ^ q;
        }
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l0, (__m128i*) h0);
    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l1, (__m128i*) h1);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);

    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output + 32);
}


#define CN_STEP1(a, b, c, l, ptr, idx)                \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);


#define CN_STEP2(a, b, c, l, ptr, idx)                                 \
    if (VARIANT == xmrig::VARIANT_TUBE) {                              \
        c = aes_round_tweak_div(c, a);                                 \
    }                                                                  \
    else if (SOFT_AES) {                                               \
        c = soft_aesenc(c, a);                                         \
    } else {                                                           \
        c = _mm_aesenc_si128(c, a);                                    \
    }                                                                  \
                                                                       \
    b = _mm_xor_si128(b, c);                                           \
                                                                       \
    if (IS_MONERO) {                                                 \
        cryptonight_monero_tweak<VARIANT == xmrig::VARIANT_XTL ? 4 : 3>(reinterpret_cast<uint64_t*>(ptr), b); \
    } else {                                                           \
        _mm_store_si128(ptr, b);                                       \
    }


#define CN_STEP3(a, b, c, l, ptr, idx)                \
    idx = EXTRACT64(c);                               \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    b = _mm_load_si128(ptr);


#define CN_STEP4(a, b, c, l, mc, ptr, idx)              \
    lo = __umul128(idx, EXTRACT64(b), &hi);             \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));       \
                                                        \
    if (IS_MONERO) {                                    \
        _mm_store_si128(ptr, _mm_xor_si128(a, mc));     \
                                                        \
        if (VARIANT == xmrig::VARIANT_TUBE ||           \
            VARIANT == xmrig::VARIANT_RTO) {            \
            ((uint64_t*)ptr)[1] ^= ((uint64_t*)ptr)[0]; \
        }                                               \
    } else {                                            \
        _mm_store_si128(ptr, a);                        \
    }                                                   \
                                                        \
    a = _mm_xor_si128(a, b);                            \
    idx = EXTRACT64(a);                                 \
                                                        \
    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {             \
        int64_t n = ((int64_t*)&l[idx & MASK])[0];      \
        int32_t d = ((int32_t*)&l[idx & MASK])[2];      \
        int64_t q = n / (d | 0x5);                      \
        ((int64_t*)&l[idx & MASK])[0] = n ^ q;          \
        if (VARIANT == xmrig::VARIANT_XHV) {            \
            d = ~d;                                     \
        }                                               \
                                                        \
        idx = d ^ q;                                    \
    }


#define CONST_INIT(ctx, n)                                                                       \
    __m128i mc##n;                                                                               \
    if (IS_MONERO) {                                                                           \
        mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(input + n * size + 35) ^       \
                               *(reinterpret_cast<const uint64_t*>((ctx)->state) + 24), 0);      \
    }


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_MONERO    = xmrig::cn_is_monero<VARIANT>();

    if (IS_MONERO && size < 43) {
        memset(output, 0, 32 * 3);
        return;
    }

    for (size_t i = 0; i < 3; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);

    for (size_t i = 0; i < ITERATIONS / 2; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
    }

    for (size_t i = 0; i < 3; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_MONERO    = xmrig::cn_is_monero<VARIANT>();

    if (IS_MONERO && size < 43) {
        memset(output, 0, 32 * 4);
        return;
    }

    for (size_t i = 0; i < 4; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
    __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);
    __m128i cx3 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2, idx3;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);
    idx3 = EXTRACT64(ax3);

    for (size_t i = 0; i < ITERATIONS / 2; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
    }

    for (size_t i = 0; i < 4; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_MONERO    = xmrig::cn_is_monero<VARIANT>();

    if (IS_MONERO && size < 43) {
        memset(output, 0, 32 * 5);
        return;
    }

    for (size_t i = 0; i < 5; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    CONST_INIT(ctx[4], 4);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint8_t* l4  = ctx[4]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[4]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
    __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
    __m128i ax4 = _mm_set_epi64x(h4[1] ^ h4[5], h4[0] ^ h4[4]);
    __m128i bx4 = _mm_set_epi64x(h4[3] ^ h4[7], h4[2] ^ h4[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);
    __m128i cx3 = _mm_set_epi64x(0, 0);
    __m128i cx4 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2, idx3, idx4;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);
    idx3 = EXTRACT64(ax3);
    idx4 = EXTRACT64(ax4);

    for (size_t i = 0; i < ITERATIONS / 2; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP1(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP2(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP3(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, bx4, cx4, l4, mc4, ptr4, idx4);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP1(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP2(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP3(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, cx4, bx4, l4, mc4, ptr4, idx4);
    }

    for (size_t i = 0; i < 5; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}

#endif /* __CRYPTONIGHT_X86_H__ */
