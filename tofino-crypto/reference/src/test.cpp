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

extern "C" {
#include "aes.h"
#include "aes_hw.h"
}

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <cstring>
#include <iostream>


TEST_CASE("128-bit key expansion")
{
    static const struct aes_key_schedule expected = {{ .w = {
        0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09,
        0x17fefaa0, 0xb12c5488, 0x3939a323, 0x05766c2a,
        0xf295c2f2, 0x43b9967a, 0x7a803559, 0x7ff65973,
        0x7d47803d, 0x3efe1647, 0x447e231e, 0x3b887a6d,
        0x41a544ef, 0x7f5b52a8, 0x3b2571b6, 0x00ad0bdb,
        0xf8c6d1d4, 0x879d837c, 0xbcb8f2ca, 0xbc15f911,
        0x7aa3886d, 0xfd3e0b11, 0x4186f9db, 0xfd9300ca,
        0x0ef7544e, 0xf3c95f5f, 0xb24fa684, 0x4fdca64e,
        0x2173d2ea, 0xd2ba8db5, 0x60f52b31, 0x2f298d7f,
        0xf36677ac, 0x21dcfa19, 0x4129d128, 0x6e005c57,
        0xa8f914d0, 0x8925eec9, 0xc80c3fe1, 0xa60c63b6,
    }}};
    static const struct aes_key key = {{ .w = {
        0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
    }}};

    SUBCASE("aes_key_expansion")
    {
        struct aes_key_schedule keySchedule = {};
        aes_key_expansion(&key, &keySchedule);

        for (size_t i = 0; i < AES_SCHED_SIZE; ++i)
        {
            CAPTURE(i);
            CHECK(keySchedule.w[i] == expected.w[i]);
        }
    }
    SUBCASE("aes_key_expansion_128")
    {
        __m128i keyReg = _mm_loadu_si128((const __m128i_u*)&key);
        __m128i keySchedule[AES_SCHED_SIZE / 4] = {};
        aes_key_expansion_128(keyReg, keySchedule);

        for (size_t i = 0; i < AES_SCHED_SIZE; ++i)
        {
            CAPTURE(i);
            CHECK(reinterpret_cast<uint32_t*>(keySchedule)[i] == expected.w[i]);
        }
    }
}

TEST_CASE("128-bit AES single block")
{
    constexpr size_t AES_TEST_VECTORS = 2;
    static const struct aes_block input[AES_TEST_VECTORS] = {
        {{ .b = {
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34
        }}},
        {{ .b = {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        }}}
    };
    static const struct aes_block expected[AES_TEST_VECTORS] = {
        {{ .b = {
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32
        }}},
        {{ .b = {
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        }}}
    };
    static const struct aes_key key[AES_TEST_VECTORS] = {
        {{ .w = {
            0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
        }}},
        {{ .w = {
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
        }}}
    };

    SUBCASE("aes_encrypt")
    {
        for (size_t i = 0; i < AES_TEST_VECTORS; ++i)
        {
            struct aes_key_schedule keySchedule = {};
            aes_key_expansion(&key[i], &keySchedule);

            struct aes_block output = {};
            aes_encrypt(&input[i], &keySchedule, &output);

            CAPTURE(i);
            for (size_t j = 0; j < 4*AES_BLOCK_SIZE; ++j)
            {
                CAPTURE(j);
                CHECK(output.b[j] == expected[i].b[j]);
            }
        }
    }
    SUBCASE("aes_encrypt_unaligned128")
    {
        for (size_t i = 0; i < AES_TEST_VECTORS; ++i)
        {
            __m128i keyReg = _mm_loadu_si128((const __m128i_u*)&key[i]);
            __m128i keySchedule[AES_SCHED_SIZE / 4] = {};
            aes_key_expansion_128(keyReg, keySchedule);

            struct aes_block output = {};
            aes_encrypt_unaligned128(&input[i], keySchedule, &output);

            CAPTURE(i);
            for (size_t j = 0; j < 4*AES_BLOCK_SIZE; ++j)
            {
                CAPTURE(j);
                CHECK(output.b[j] == expected[i].b[j]);
            }
        }
    }
}

TEST_CASE("AES-CMAC")
{
    constexpr size_t CMAC_TEST_VECTORS = 4;
    static const uint8_t message[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    static const size_t msgLength[CMAC_TEST_VECTORS] = {
        0, 16, 40, 64
    };
    static const struct aes_key key = {{ .w = {
        0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
    }}};
    static const struct aes_cmac expected[CMAC_TEST_VECTORS] = {
        {{ .w = { 0x29691dbb, 0x283759e9, 0x127da37f, 0x4667759b }}},
        {{ .w = { 0xb4160a07, 0x44414d6b, 0x9ddd9bf7, 0x7c284ad0 }}},
        {{ .w = { 0x4767a6df, 0x30e69ade, 0x6132ca30, 0x27c89714 }}},
        {{ .w = { 0xbfbef051, 0x929d3b7e, 0x177449fc, 0xfe3c3679 }}}
    };

    SUBCASE("software")
    {
        struct aes_key_schedule keySchedule = {};
        aes_key_expansion(&key, &keySchedule);
        struct aes_block subkeys[2] = {};
        aes_cmac_subkeys(&keySchedule, subkeys);

        SUBCASE("aes_cmac")
        {
            for (size_t i = 0; i < CMAC_TEST_VECTORS; ++i)
            {
                struct aes_cmac mac = {};
                aes_cmac(message, msgLength[i], &keySchedule, subkeys, &mac);

                INFO("length = ", msgLength[i]);
                for (size_t j = 0; j < AES_KEY_LENGTH; ++j)
                {
                    CAPTURE(j);
                    CHECK(mac.w[j] == expected[i].w[j]);
                }
            }
        }
    }
    SUBCASE("hardware")
    {
        __m128i keyReg = _mm_loadu_si128((const __m128i_u*)&key);
        __m128i keySchedule[AES_SCHED_SIZE / 4] = {};
        aes_key_expansion_128(keyReg, keySchedule);

        __m128i subkeys[2] = {};
        aes_cmac_subkeys_128(keySchedule, subkeys);

        SUBCASE("aes_cmac_unaligned128")
        {
            for (size_t i = 0; i < CMAC_TEST_VECTORS; ++i)
            {
                struct aes_cmac mac = {};
                aes_cmac_unaligned128(message, msgLength[i], keySchedule, subkeys, &mac);

                INFO("length = ", msgLength[i]);
                for (size_t j = 0; j < AES_KEY_LENGTH; ++j)
                {
                    CAPTURE(j);
                    CHECK(mac.w[j] == expected[i].w[j]);
                }
            }
        }
    }
}
