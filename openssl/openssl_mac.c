/**
 * MIT License
 * 
 * Copyright (c) 2018 Ilwoong Jeong, https://github.com/ilwoong
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../print_hex.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void CheckError(int state) {
    if (state != 1) {
        printf("State: %d\n", state);
        handleErrors();
    }
}

void hmac(const EVP_MD* type, const uint8_t* key, size_t keylen, const uint8_t* msg, size_t length, uint8_t* hmac)
{
    size_t vlen = 0;

    EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keylen);
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        handleErrors();
    }

    CheckError(EVP_DigestInit_ex(ctx, type, NULL));
    CheckError(EVP_DigestSignInit(ctx, NULL, type, NULL, pkey));
    CheckError(EVP_DigestSignUpdate(ctx, msg, length));
    CheckError(EVP_DigestSignFinal(ctx, hmac, &vlen));

    EVP_MD_CTX_destroy(ctx);
}

int main()
{
    const EVP_MD* type = EVP_sha256();    
    const uint8_t* msg = "A quick brown fox jumps over the lazy dog.";
    uint8_t key[32] = { 0, };
    uint8_t mac[64] = { 0, };
    unsigned length = 0;

    printf("HMAC\n");

    hmac(EVP_sha256(), key, 32, msg, 42, mac);
    print_hex("    HMAC-SHA256:", mac, 32);

    return 0;
}