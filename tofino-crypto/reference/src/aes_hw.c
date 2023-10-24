// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2023 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// \file
/// AES and AES-CMAC with hardware support

#include "aes_hw.h"
#include "aes.h"

#include <stdalign.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>


#define AES_KEY_EXPANSION_ROUND(key, temp, rcon) \
    temp = _mm_aeskeygenassist_si128(key, rcon); \
    temp = _mm_shuffle_epi32(temp, 0xff); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, temp)

/// \brief Calculate the key schedule with hardware assistance.
/// \param[in] key AES key
/// \param[out] key_schedule Initial four words + 10 round keys
void aes_key_expansion_128(__m128i key, __m128i key_schedule[AES_SCHED_SIZE / 4])
{
    __m128i temp;
    __m128i *dest = (__m128i*)key_schedule;
    _mm_store_si128(dest++, key);

    // Round 1
    AES_KEY_EXPANSION_ROUND(key, temp, 0x01);
    _mm_store_si128(dest++, key);

    // Round 2
    AES_KEY_EXPANSION_ROUND(key, temp, 0x02);
    _mm_store_si128(dest++, key);

    // Round 3
    AES_KEY_EXPANSION_ROUND(key, temp, 0x04);
    _mm_store_si128(dest++, key);

    // Round 4
    AES_KEY_EXPANSION_ROUND(key, temp, 0x08);
    _mm_store_si128(dest++, key);

    // Round 5
    AES_KEY_EXPANSION_ROUND(key, temp, 0x10);
    _mm_store_si128(dest++, key);

    // Round 6
    AES_KEY_EXPANSION_ROUND(key, temp, 0x20);
    _mm_store_si128(dest++, key);

    // Round 7
    AES_KEY_EXPANSION_ROUND(key, temp, 0x40);
    _mm_store_si128(dest++, key);

    // Round 8
    AES_KEY_EXPANSION_ROUND(key, temp, 0x80);
    _mm_store_si128(dest++, key);

    // Round 9
    AES_KEY_EXPANSION_ROUND(key, temp, 0x1b);
    _mm_store_si128(dest++, key);

    // Round 10
    AES_KEY_EXPANSION_ROUND(key, temp, 0x36);
    _mm_store_si128(dest++, key);
}

/// \brief Encrypt a block using AES-NI instructions.
/// \param[in] input Input block
/// \param[in] key_schedule AES round keys
/// \return Encrypted output block
__m128i aes_encrypt_128(const __m128i input, const __m128i key_schedule[AES_SCHED_SIZE / 4])
{
    // Initialization (round 0)
    __m128i state = input;
    state = _mm_xor_si128(state, _mm_load_si128(key_schedule));

    // First 9 rounds
    for (size_t round = 1; round < AES_ROUNDS; ++round)
        state = _mm_aesenc_si128(state, _mm_load_si128(key_schedule + round));

    // Last round
    state = _mm_aesenclast_si128(state, _mm_load_si128(key_schedule + AES_ROUNDS));

    return state;
}

/// \brief Encrypt a block with the given key schedule.
/// \param[in] input Input block
/// \param[in] key_schedule AES round keys
/// \param[out] ouput Encrypted output block
void aes_encrypt_unaligned128(
    const struct aes_block *input,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    struct aes_block *output)
{
    __m128i block = _mm_loadu_si128((const __m128i_u*)input);
    block = aes_encrypt_128(block, key_schedule);
    _mm_storeu_si128((__m128i_u*)output, block);
}

/// \brief Performs part of the subkey derivation procedure.
/// \param[inout] subkey
static __m128i generate_subkey_helper(__m128i subkey)
{
    static const uint64_t alignas(16) msb_mask[2] = { 1ull << 7, 0 };
    static const uint64_t alignas(16) const_rb[2] = { 0, 0x87ull << 56 };
    static const uint8_t alignas(16) shuffle[16] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    };

    // Extract MSB
    __m128i c1 = _mm_load_si128((const __m128i*)msb_mask);
    int msb = _mm_testz_si128(subkey, c1) == 0;

    // Reverse byte order
    __m128i shuffle_ctrl = _mm_load_si128((const __m128i*)shuffle);
    subkey = _mm_shuffle_epi8(subkey, shuffle_ctrl);

    // Shift left by one bit
    __m128i carry = _mm_srli_epi64(_mm_bslli_si128(subkey, 8), 63);
    subkey = _mm_slli_epi64(subkey, 1);
    subkey = _mm_or_si128(subkey, carry);

    // Reverse byte order
    subkey = _mm_shuffle_epi8(subkey, shuffle_ctrl);

    // Adjust LSB if MSB was set
    if (msb)
    {
        __m128i c2 = _mm_load_si128((const __m128i*)const_rb);
        subkey = _mm_xor_si128(subkey, c2);
    }

    return subkey;
}

/// \brief Generate the first and second sunkey needed by the AES-CMAC algorithm.
/// \param[in] key_schedule AES round keys
/// \param[in] subkeys First subkey followed by the second subkey
void aes_cmac_subkeys_128(const __m128i key_schedule[AES_SCHED_SIZE / 4], __m128i subkeys[2])
{
    // First subkey
    __m128i subkey = _mm_setzero_si128();
    subkey = aes_encrypt_128(subkey, key_schedule);
    subkey = generate_subkey_helper(subkey);
    _mm_store_si128(subkeys, subkey);

    // Second subkey
    subkey = generate_subkey_helper(subkey);
    _mm_store_si128(subkeys + 1, subkey);
}

/// \brief Calculate the AES-CMAC according to RFC4493.
/// \param[in] data Input data
/// \param[in] len Size of the input data in bytes
/// \param[in] key_schedule AES round keys
/// \param[in] subkeys Subkeys derived from the main key by aes_cmac_subkeys()
/// \param[out] mac Computed MAC
void aes_cmac_unaligned128(
    const uint8_t *data, size_t len,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    const __m128i subkeys[2],
    struct aes_cmac *mac)
{
    uint8_t alignas(16) staging[16] = {};
    __m128i subkey = subkeys[0];

    // Process input block-by-block
    __m128i state = _mm_setzero_si128();
    size_t offset = 0;
    do {
        size_t i = 0;
        for (; i < 4*AES_BLOCK_SIZE && (offset + i) < len; ++i)
            staging[i] = data[offset + i];

        // Special treatment of the last block
        if (offset + 4*AES_BLOCK_SIZE >= len)
        {
            if (i < 4*AES_BLOCK_SIZE)
            {
                // Padding
                staging[i++] = 0x80;
                for (; i < 4*AES_BLOCK_SIZE; ++i)
                    staging[i] = 0x00;
                // Use second subkey
                subkey = subkeys[1];
            }
            state = _mm_xor_si128(state, subkey);
        }

        state = _mm_xor_si128(state, _mm_load_si128((__m128i*)staging));
        state = aes_encrypt_128(state, key_schedule);
        offset += 4*AES_BLOCK_SIZE;
    }
    while (offset < len);

    _mm_storeu_si128((__m128i_u*)mac, state);
}
