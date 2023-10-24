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
/// \brief AES key expansion, encryption, and MAC computation.

#ifndef AES_H_GUARD
#define AES_H_GUARD

#include <stddef.h>
#include <stdint.h>


#define AES_KEY_LENGTH 4
#define AES_BLOCK_SIZE 4
#define AES_ROUNDS 10
#define AES_SCHED_SIZE (AES_ROUNDS+1)*AES_BLOCK_SIZE
#define AES_CMAC_NO_LOOP_MAX_BYTES 4 * (4*AES_BLOCK_SIZE)


/// \brief A 16 byte / 128 bit block for AES.
struct aes_block
{
    union {
        uint8_t b[4*AES_BLOCK_SIZE];
        uint32_t w[AES_BLOCK_SIZE];
    };
};

/// \brief 128-bit AES key
struct aes_key
{
    union {
        uint8_t b[4*AES_KEY_LENGTH];
        uint32_t w[AES_KEY_LENGTH];
    };
};

/// \brief AES key schedule containing initialization data (the AES key) followed by 10 round keys.
struct aes_key_schedule
{
    union {
        uint8_t b[4*AES_SCHED_SIZE];
        uint32_t w[AES_SCHED_SIZE];
        struct aes_key k[AES_ROUNDS+1];
    };
};

/// \brief Holds a MAC computed by the AES-CMAC algorithm.
struct aes_cmac
{
    union {
        uint8_t b[4*AES_KEY_LENGTH];
        uint32_t w[AES_KEY_LENGTH];
    };
};


/// \brief AES substitution table
extern const uint8_t AES_SBox[256];

void aes_key_expansion(
    const struct aes_key *key,
    struct aes_key_schedule *key_schedule);

int aes_encrypt(
    const struct aes_block *input,
    const struct aes_key_schedule *key_schedule,
    struct aes_block *output);

void aes_cmac_subkeys(
    const struct aes_key_schedule *key_schedule,
    struct aes_block subkeys[2]);

void aes_cmac(
    const uint8_t *data, size_t len,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block subkeys[2],
    struct aes_cmac *mac);


/// \brief Calculate the AES-CMAC of a 16 byte block according to RFC4493.
/// \param[in] data Input data, must be exactly 16 bytes
/// \param[in] key_schedule AES round keys
/// \param[in] subkey First subkey derived from the main key by aes_cmac_subkeys()
/// \param[out] mac Computed MAC
inline void aes_cmac_16bytes(
    const struct aes_block *data,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block *subkey,
    struct aes_cmac *mac)
{
    // XOR data and subkey
    for (size_t i = 0; i < 4*AES_BLOCK_SIZE; ++i)
        mac->b[i] = data->b[i] ^ subkey->b[i];

    // Invoke block cipher
    aes_encrypt((struct aes_block*)mac, key_schedule, (struct aes_block*)mac);
}

#endif // AES_H_GUARD
