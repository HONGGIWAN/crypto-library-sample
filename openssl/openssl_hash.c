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

void hash(const EVP_MD* type, const uint8_t* msg, size_t length, uint8_t* digest, unsigned int* digest_length)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        handleErrors();
    }

    CheckError(EVP_DigestInit_ex(ctx, type, NULL));
    CheckError(EVP_DigestUpdate(ctx, msg, length));
    CheckError(EVP_DigestFinal_ex(ctx, digest, digest_length));

    EVP_MD_CTX_destroy(ctx);
}

void test_pbkdf2() 
{
    const char* password = "A quick brown fox jumps over the lazy dog.";
    size_t passlen = 42;

    const EVP_MD *digest = EVP_sha256();
    size_t iterations = 1000;

    const char* salt = "sun-dried salt";
    size_t saltlen = 14;

    uint8_t out[16] = {0,};
    size_t outlen = 16;

    PKCS5_PBKDF2_HMAC(password, passlen, salt, saltlen, iterations, digest, outlen, out);

    printf("PBKDF-HMAC-SHA256\n");    
    print_hex("    password", password, passlen);
    print_hex("        salt", salt, saltlen);
    printf("  iterations: %ld\n", iterations);
    print_hex("      PBKDF2", out, outlen);
}


int main()
{
    const EVP_MD* type = EVP_sha256();    
    const uint8_t* msg = "A quick brown fox jumps over the lazy dog.";
    uint8_t digest[64] = { 0, };
    unsigned length = 0;

    printf("Message Digest\n");
    hash(EVP_md5(), msg, 42, digest, &length);
    print_hex("       MD5", digest, length);

    hash(EVP_sha1(), msg, 42, digest, &length);
    print_hex("      SHA1", digest, length);

    hash(EVP_sha256(), msg, 42, digest, &length);
    print_hex("    SHA256", digest, length);

    printf("\n");
    test_pbkdf2();

    return 0;
}