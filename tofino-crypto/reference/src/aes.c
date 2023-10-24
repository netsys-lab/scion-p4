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
/// \brief Implementation of AES and AES-CMAC.

#include "aes.h"
#include <string.h>


const uint8_t AES_SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t AES_Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

extern const uint32_t AES_T0[256];
extern const uint32_t AES_T1[256];
extern const uint32_t AES_T2[256];
extern const uint32_t AES_T3[256];


/// \brief Apply S-box substitutions to a word.
static uint32_t sub_word(uint32_t word)
{
    uint32_t result = 0;
    result |= AES_SBox[word & 0xff];
    result |= (AES_SBox[(word >> 8) & 0xff]) << 8;
    result |= (AES_SBox[(word >> 16) & 0xff]) << 16;
    result |= (AES_SBox[(word >> 24) & 0xff]) << 24;
    return result;
}

/// \brief Perform a cyclic permutation on the input word.
static uint32_t rot_word(uint32_t word)
{
    uint32_t result = 0;
    result |= (word >> 8) & 0xffffff;
    result |= (word & 0xff) << 24;
    return result;
}

/// \brief Calculate the key schedule.
/// \param[in] key AES key
/// \param[out] key_schedule Initial four words + 10 round keys
void aes_key_expansion(
    const struct aes_key *key,
    struct aes_key_schedule *key_schedule)
{
    uint32_t temp = 0;

    // The key itself is needed to initialize the state matrix
    memcpy(key_schedule, key, sizeof(uint32_t)*AES_KEY_LENGTH);

    // Generate 10 round keys
    for (unsigned int i = AES_KEY_LENGTH; i < AES_SCHED_SIZE; ++i)
    {
        temp = key_schedule->w[i - 1];
        if (i % AES_KEY_LENGTH == 0)
            temp = sub_word(rot_word(temp)) ^ AES_Rcon[i / AES_KEY_LENGTH];
        key_schedule->w[i] = key_schedule->w[i - AES_KEY_LENGTH] ^ temp;
    }
}

/// \brief Encrypt a block with the given key schedule.
/// \param[in] input Input block
/// \param[in] key_schedule AES round keys
/// \param[out] ouput Encrypted output block
int aes_encrypt(
    const struct aes_block *input,
    const struct aes_key_schedule *key_schedule,
    struct aes_block *output)
{
    // The state matrix is stored in column-major order
    struct aes_block state;
    for (unsigned int i = 0; i < 4; ++i) state.w[i] = input->w[i] ^ key_schedule->k[0].w[i];

    // First 9 rounds
    for (unsigned int round = 1; round < AES_ROUNDS; ++round)
    {
        uint32_t c[4];
        c[0] = AES_T0[state.w[0]&0xff] ^ AES_T1[state.w[1]>>8&0xff] ^ AES_T2[state.w[2]>>16&0xff] ^ AES_T3[state.w[3]>>24&0xff];
        c[1] = AES_T0[state.w[1]&0xff] ^ AES_T1[state.w[2]>>8&0xff] ^ AES_T2[state.w[3]>>16&0xff] ^ AES_T3[state.w[0]>>24&0xff];
        c[2] = AES_T0[state.w[2]&0xff] ^ AES_T1[state.w[3]>>8&0xff] ^ AES_T2[state.w[0]>>16&0xff] ^ AES_T3[state.w[1]>>24&0xff];
        c[3] = AES_T0[state.w[3]&0xff] ^ AES_T1[state.w[0]>>8&0xff] ^ AES_T2[state.w[1]>>16&0xff] ^ AES_T3[state.w[2]>>24&0xff];
        for (unsigned int i = 0; i < 4; ++i) state.w[i] = c[i] ^ key_schedule->k[round].w[i];
    }

    // Last round
    uint32_t c[4];
    c[0] = (uint32_t)AES_SBox[state.w[0]&0xff] ^ (uint32_t)AES_SBox[state.w[1]>>8&0xff]<<8 ^ (uint32_t)AES_SBox[state.w[2]>>16&0xff]<<16 ^ (uint32_t)AES_SBox[state.w[3]>>24&0xff]<<24;
    c[1] = (uint32_t)AES_SBox[state.w[1]&0xff] ^ (uint32_t)AES_SBox[state.w[2]>>8&0xff]<<8 ^ (uint32_t)AES_SBox[state.w[3]>>16&0xff]<<16 ^ (uint32_t)AES_SBox[state.w[0]>>24&0xff]<<24;
    c[2] = (uint32_t)AES_SBox[state.w[2]&0xff] ^ (uint32_t)AES_SBox[state.w[3]>>8&0xff]<<8 ^ (uint32_t)AES_SBox[state.w[0]>>16&0xff]<<16 ^ (uint32_t)AES_SBox[state.w[1]>>24&0xff]<<24;
    c[3] = (uint32_t)AES_SBox[state.w[3]&0xff] ^ (uint32_t)AES_SBox[state.w[0]>>8&0xff]<<8 ^ (uint32_t)AES_SBox[state.w[1]>>16&0xff]<<16 ^ (uint32_t)AES_SBox[state.w[2]>>24&0xff]<<24;
    for (unsigned int i = 0; i < 4; ++i) state.w[i] = c[i] ^ key_schedule->k[AES_ROUNDS].w[i];

    *output = state;
    return 0;
}

/// \brief Performs part of the subkey derivation procedure.
/// \param[inout] subkey
static void generate_subkey_helper(struct aes_block *subkey)
{
    uint8_t msb = subkey->b[0] >> 7;

    // Shift L to the left by one bit
    for (unsigned int i = 0; i < 4*AES_BLOCK_SIZE - 1; ++i)
        subkey->b[i] = (subkey->b[i] << 1) | (subkey->b[i + 1] >> 7);
    subkey->b[15] <<= 1;

    if (msb) subkey->b[15] ^= 0x87;
}

/// \brief Generate the first and second subkey needed by the AES-CMAC algorithm.
/// \param[in] key_schedule AES round keys
/// \param[in] subkeys First subkey followed by the second subkey
void aes_cmac_subkeys(
    const struct aes_key_schedule *key_schedule,
    struct aes_block subkeys[2])
{
    // First subkey
    memset(subkeys, 0, 4*AES_KEY_LENGTH);
    aes_encrypt(&subkeys[0], key_schedule, &subkeys[0]);
    generate_subkey_helper(&subkeys[0]);

    // Second subkey
    subkeys[1] = subkeys[0];
    generate_subkey_helper(&subkeys[1]);
}

/// \brief Calculate the AES-CMAC according to RFC4493.
/// \param[in] data Input data
/// \param[in] len Size of the input data in bytes
/// \param[in] key_schedule AES round keys
/// \param[in] subkeys Subkeys derived from the main key by aes_cmac_subkeys()
/// \param[out] mac Computed MAC
void aes_cmac(
    const uint8_t *data, size_t len,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block subkeys[2],
    struct aes_cmac *mac)
{
    const uint8_t* subkey = subkeys[0].b;

    // Process input block-by-block
    struct aes_block state = {};
    size_t offset = 0;
    do {
        size_t i = 0;
        for (; i < 4*AES_BLOCK_SIZE && (offset + i) < len; ++i)
            state.b[i] ^= data[offset + i];

        // Special treatment of the last block
        if (offset + 4*AES_BLOCK_SIZE >= len)
        {
            if (i < 4*AES_BLOCK_SIZE)
            {
                state.b[i] ^= 0x80;    // padding
                subkey = subkeys[1].b; // use second subkey
            }
            // XOR subkey
            for (size_t j = 0; j < 4*AES_BLOCK_SIZE; ++j)
                state.b[j] ^= subkey[j];
        }

        aes_encrypt(&state, key_schedule, &state);
        offset += 4*AES_BLOCK_SIZE;
    }
    while (offset < len);

    memcpy(mac, &state, 4*AES_BLOCK_SIZE);
}

/// \brief Calculate the AES-CMAC according to RFC4493.
/// \param[in] data Input data
/// \param[in] len Size of the input data in bytes. Must be less then or equal to
///                `AES_CMAC_NO_LOOP_MAX_BYTES`.
/// \param[in] key_schedule AES round keys
/// \param[in] subkeys Subkeys derived from the main key by aes_cmac_subkeys()
/// \param[out] mac Computed MAC
void aes_cmac_no_loops(
    const uint8_t *data, size_t len,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block subkeys[2],
    struct aes_cmac *mac)
{
    const uint8_t* subkey = subkeys[0].b;
    size_t blocks = 1, lastBlockBytes = 0;
    if (len > 0)
    {
        blocks = (len + 4*AES_BLOCK_SIZE - 1) / (4*AES_BLOCK_SIZE);
        lastBlockBytes = len % (4*AES_BLOCK_SIZE);
        if (lastBlockBytes == 0) lastBlockBytes = 4*AES_BLOCK_SIZE;
    }

    struct aes_block state = {};
    size_t offset = 0;
    switch (blocks)
    {
    default:
    case 4:
        for (size_t i = 0; i < 4*AES_BLOCK_SIZE; ++i)
            state.b[i] ^= data[offset + i];
        aes_encrypt(&state, key_schedule, &state);
        offset += 4*AES_BLOCK_SIZE;
        __attribute__((fallthrough));
    case 3:
        for (size_t i = 0; i < 4*AES_BLOCK_SIZE; ++i)
            state.b[i] ^= data[offset + i];
        aes_encrypt(&state, key_schedule, &state);
        offset += 4*AES_BLOCK_SIZE;
        __attribute__((fallthrough));
    case 2:
        for (size_t i = 0; i < 4*AES_BLOCK_SIZE; ++i)
            state.b[i] ^= data[offset + i];
        aes_encrypt(&state, key_schedule, &state);
        offset += 4*AES_BLOCK_SIZE;
        __attribute__((fallthrough));
    case 1:
    {
        size_t i = 0;
        for (; i < lastBlockBytes; ++i)
            state.b[i] ^= data[offset + i];

        if (lastBlockBytes < 4*AES_BLOCK_SIZE)
        {
            state.b[i] ^= 0x80;     // padding
            subkey = subkeys[1].b; // use second subkey
        }
        // XOR subkey
        for (size_t j = 0; j < 4*AES_BLOCK_SIZE; ++j)
            state.b[j] ^= subkey[j];
        aes_encrypt(&state, key_schedule, &state);
    }
    }

    memcpy(mac, &state, 4*AES_BLOCK_SIZE);
}
