/**
 * The MIT License
 *
 * Copyright (c) 2018-2020 Ilwoong Jeong (https://github.com/ilwoong)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "../print_hex.h"

AES_KEY key;
uint8_t pkey[32] = { 0, };
uint8_t iv[16] = { 0, };
uint8_t pt[32] = { 0, };
uint8_t encrypted[48] = { 0, };
uint8_t decrypted[48] = { 0xff, };

void print_result(const char* title, const uint8_t* encrypted, const uint8_t* decrypted)
{
    printf("%s\n", title);
    print_hex("    ENC", encrypted, 32);
    print_hex("    DEC", decrypted, 32);
    printf("\n");
}

void aes256_ecb(uint8_t* out, const uint8_t* in, size_t length, const uint8_t* key, const int enc)
{
    AES_KEY aes_key;
    if (enc == AES_ENCRYPT) {
        AES_set_encrypt_key(key, 256, &aes_key);
    } else {
        AES_set_decrypt_key(key, 256, &aes_key);
    }

    while (length >= 16) {
        AES_ecb_encrypt(in, out, &aes_key, enc);

        in += 16;
        out += 16;
        length -= 16;
    }
}

void aes256_cbc(uint8_t* out, const uint8_t* in, size_t length, const uint8_t* key, const uint8_t* iv, const int enc)
{
    AES_KEY aes_key;
    if (enc == AES_ENCRYPT) {
        AES_set_encrypt_key(key, 256, &aes_key);
    } else {
        AES_set_decrypt_key(key, 256, &aes_key);
    }

    uint8_t eiv[16] = {0};
    memcpy(eiv, iv, 16);

    AES_cbc_encrypt(in, out, length, &aes_key, eiv, enc);
}

void aes256_cfb(uint8_t* out, const uint8_t* in, size_t length, const uint8_t* key, const uint8_t* iv, const int enc)
{
    int num = 0;
    uint8_t eiv[16] = {0};
    memcpy(eiv, iv, 16);

    AES_KEY aes_key;    
    AES_set_encrypt_key(key, 256, &aes_key);

    AES_cfb128_encrypt(in, out, length, &aes_key, eiv, &num, enc);
}

void aes256_ofb(uint8_t* out, const uint8_t* in, size_t length, const uint8_t* key, const uint8_t* iv)
{
    int num = 0;
    uint8_t eiv[16] = {0};
    memcpy(eiv, iv, 16);

    AES_KEY aes_key;    
    AES_set_encrypt_key(key, 256, &aes_key);

    AES_ofb128_encrypt(in, out, length, &aes_key, eiv, &num);
}

void aes256_ctr(uint8_t* out, const uint8_t* in, size_t length, const uint8_t* key, const uint8_t* ctr)
{
    int num = 0;
    uint8_t cctr[16] = {0};
    uint8_t ectr[16] = {0};
    memcpy(cctr, ctr, 16);

    AES_KEY aes_key;    
    AES_set_encrypt_key(key, 256, &aes_key);

    CRYPTO_ctr128_encrypt(in, out, length, &aes_key, cctr, ectr, &num, (block128_f)AES_encrypt);
}

void aes_ecb_sample() 
{
    aes256_ecb(encrypted, pt, 32, pkey, AES_ENCRYPT);
    aes256_ecb(decrypted, encrypted, 32, pkey, AES_DECRYPT);

    print_result("AES_256_ECB", encrypted, decrypted);
}

void aes_cbc_sample() 
{
    aes256_cbc(encrypted, pt, 32, pkey, iv, AES_ENCRYPT);
    aes256_cbc(decrypted, encrypted, 32, pkey, iv, AES_DECRYPT);
    
    print_result("AES_256_CBC", encrypted, decrypted);
}

void aes_cfb_sample() 
{
    aes256_cfb(encrypted, pt, 32, pkey, iv, AES_ENCRYPT);
    aes256_cfb(decrypted, encrypted, 32, pkey, iv, AES_DECRYPT);
    
    print_result("AES_256_CFB", encrypted, decrypted);
}

void aes_ofb_sample() 
{
    aes256_ofb(encrypted, pt, 32, pkey, iv);
    aes256_ofb(decrypted, encrypted, 32, pkey, iv);
    
    print_result("AES_256_OFB", encrypted, decrypted);
}

void aes_ctr_sample()
{
    aes256_ctr(encrypted, pt, 32, pkey, iv);
    aes256_ctr(decrypted, encrypted, 32, pkey, iv);
    
    print_result("AES_256_CTR", encrypted, decrypted);
}

static void makeSequelData(uint8_t* data, uint8_t start, size_t length) {
    for (int i = 0; i < length; ++i) {
        data[i] = (start++);
    }
}

int main()
{
    makeSequelData(pkey, 0, 32);
    makeSequelData(iv, 32, 16);
    makeSequelData(pt, 48, 32);

    print_hex("   KEY", pkey, 32);
    print_hex("IV/CTR", iv, 16);
    print_hex("    PT", pt, 32);
    printf("\n");

    aes_ecb_sample();
    aes_cbc_sample();
    aes_cfb_sample();
    aes_ofb_sample();
    aes_ctr_sample();

    return 0;
}