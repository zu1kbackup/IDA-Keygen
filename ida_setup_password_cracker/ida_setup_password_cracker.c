/* MIT License
*
* Copyright (c) namazso 2019
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

// Based on writeup at https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/

#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mbedtls/sha1.h"

void make_candidate(wchar_t* out, uint32_t srand_seed)
{
  const static char alphabet[] = "abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";

  uint64_t seed = (((uint64_t)srand_seed) << 16) + 0x330e;

  // skip one for 7.2
  seed = (seed * 0x5DEECE66D + 0xB) & 0xFFFFFFFFFFFF;

  for (int i = 0; i < 12; ++i)
  {
    seed = (seed * 0x5DEECE66D + 0xB) & 0xFFFFFFFFFFFF;
    const size_t idx = (size_t)(ldexp((double)seed, -48) * 54.0);
    out[i] = alphabet[idx];
  }

  out[12] = 0;
}

int main()
{
  const static uint8_t salt1[17] = "PasswordCheckHash";

  // Leaked (and already publicly cracked) IDA Pro 7.2
  const static uint8_t salt2[8] = { 0xc4, 0x16, 0x39, 0x79, 0x28, 0x46, 0xe4, 0x56 };
  const static uint8_t target_hash[20] = { 0xf2, 0x9f, 0x55, 0xf0, 0x7c, 0x04, 0x3a, 0xd3, 0x4b, 0x3d, 0xe1, 0x50, 0x50, 0x15, 0x35, 0xf4, 0x44, 0x24, 0xed, 0xad };

  mbedtls_sha1_context ctx;
  mbedtls_sha1_init(&ctx);
  mbedtls_sha1_starts_ret(&ctx);
  mbedtls_sha1_update_ret(&ctx, salt1, sizeof(salt1));
  mbedtls_sha1_update_ret(&ctx, salt2, sizeof(salt2));
  wchar_t meme[13];
  const time_t begin = time(NULL);
  uint32_t i;// = 948301080;
  for(i = 1; i; ++i)
  {
    if (i % 0x1000000 == 0)
    {
      const time_t current = time(NULL);
      const time_t diff = current - begin;
      const unsigned step = i >> 24;
      printf("%d / 255 time spent %lld ETA %lld\n", i >> 24, diff, (255 - step) * diff / step);
    }

    make_candidate(meme, i);
    mbedtls_sha1_context lctx = ctx;
    mbedtls_sha1_update_ret(&lctx, (uint8_t*)meme, sizeof(meme) - 2);
    uint8_t hash[20];
    mbedtls_sha1_finish_ret(&lctx, hash);

    if (0 == memcmp(hash, target_hash, sizeof(hash)))
    {
      printf("%u %ws\n", i, meme);
      break;
    }
  }
  printf("Search ended.");
}

void mbedtls_platform_zeroize(void *buf, size_t len)
{
  memset(buf, 0, len);
}