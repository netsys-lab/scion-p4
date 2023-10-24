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

#ifndef AES_HW_ACCEL_H_GUARD
#define AES_HW_ACCEL_H_GUARD

#include "aes.h"
#include <emmintrin.h>


void aes_key_expansion_128(__m128i key, __m128i key_schedule[AES_SCHED_SIZE / 4]);

__m128i aes_encrypt_128(const __m128i input, const __m128i key_schedule[AES_SCHED_SIZE / 4]);

void aes_encrypt_unaligned128(
    const struct aes_block *input,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    struct aes_block *output);

void aes_cmac_subkeys_128(const __m128i key_schedule[AES_SCHED_SIZE / 4], __m128i subkeys[2]);

void aes_cmac_unaligned128(
    const uint8_t *data, size_t len,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    const __m128i subkeys[2],
    struct aes_cmac *mac);

#endif // AES_HW_ACCEL_H_GUARD
