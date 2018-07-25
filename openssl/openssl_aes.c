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
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <openssl/aes.h>
#include "../print_hex.h"

AES_KEY key;
uint8_t pkey[32] = { 0, };
uint8_t iv[16] = { 0, };
uint8_t pt[32] = { 0, };
uint8_t encrypted[48] = { 0, };
uint8_t decrypted[48] = { 0xff, };

void aes_ecb_sample() 
{
    AES_set_encrypt_key(pkey, 256, &key);
    AES_ecb_encrypt(pt, encrypted, &key, AES_ENCRYPT);
    AES_ecb_encrypt(pt + 16, encrypted + 16, &key, AES_ENCRYPT);

    AES_set_decrypt_key(pkey, 256, &key);
    AES_ecb_encrypt(encrypted, decrypted, &key, AES_DECRYPT);
    AES_ecb_encrypt(encrypted + 16, decrypted + 16, &key, AES_DECRYPT);

    printf("AES_256_ECB\n");
    print_hex("    ENC", encrypted, 32);
    print_hex("    DEC", decrypted, 32);
    printf("\n");
}

void aes_cbc_sample() 
{
    uint8_t local_iv[16] = {0};
    memcpy(local_iv, iv, 16);

    AES_set_encrypt_key(pkey, 256, &key);
    AES_cbc_encrypt(pt, encrypted, 32, &key, local_iv, AES_ENCRYPT);

    memcpy(local_iv, iv, 16);
    AES_set_decrypt_key(pkey, 256, &key);
    AES_cbc_encrypt(encrypted, decrypted, 32, &key, local_iv, AES_DECRYPT);
    
    printf("AES_256_CBC\n");
    print_hex("    ENC", encrypted, 32);
    print_hex("    DEC", decrypted, 32);
    printf("\n");
}

void aes_cfb_sample() 
{
    int num = 0;
    uint8_t local_iv[16] = {0};
    memcpy(local_iv, iv, 16);

    AES_set_encrypt_key(pkey, 256, &key);
    AES_cfb128_encrypt(pt, encrypted, 32, &key, local_iv, &num, AES_ENCRYPT);

    memcpy(local_iv, iv, 16);
    // AES_set_decrypt_key(pkey, 256, &key); // -> CFB uses only encryption
    AES_cfb128_encrypt(encrypted, decrypted, 32, &key, local_iv, &num, AES_DECRYPT);
    
    printf("AES_256_CFB\n");
    print_hex("    ENC", encrypted, 32);
    print_hex("    DEC", decrypted, 32);
    printf("\n");
}

void aes_ofb_sample() 
{
    int num = 0;
    uint8_t local_iv[16] = {0};
    memcpy(local_iv, iv, 16);

    AES_set_encrypt_key(pkey, 256, &key);
    AES_ofb128_encrypt(pt, encrypted, 32, &key, local_iv, &num);

    memcpy(local_iv, iv, 16);
    // AES_set_decrypt_key(pkey, 256, &key); // -> OFB uses only encryption
    AES_ofb128_encrypt(encrypted, decrypted, 32, &key, local_iv, &num);
    
    printf("AES_256_OFB\n");
    print_hex("    ENC", encrypted, 32);
    print_hex("    DEC", decrypted, 32);
    printf("\n");
}

int main() 
{
    aes_ecb_sample();
    aes_cbc_sample();
    aes_cfb_sample();
    aes_ofb_sample();
    //AES_ctr128_encrypt was deprecated at OpenSSL 1.1.0

    return 0;
}