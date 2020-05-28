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

#include <cstdint>
#include <cstring>

#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/lea.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>

#include "../print_hex.h"

using namespace CryptoPP;

void print_result(const char* title, const uint8_t* enc, const uint8_t* dec, size_t length)
{
    printf("%s\n", title);
    print_hex("    ENC", enc, length);
    print_hex("    DEC", dec, length);
    printf("\n");
}

void randomize(uint8_t* key, size_t keylen, uint8_t* iv, size_t ivlen) 
{
    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(key, keylen);
    rnd.GenerateBlock(iv, ivlen);
}

void lea_ecb_sample(bool useRandomKeyAndIv) 
{
    const size_t keysize = 32;
    const size_t length = 32;
    uint8_t key[keysize] = { 0 };
    uint8_t pt[length] = { 0 };
    uint8_t encrypted[length + 16] = { 0 };
    uint8_t decrypted[length] = { 0 };

    if (useRandomKeyAndIv) {
        AutoSeededRandomPool rnd;
        rnd.GenerateBlock(key, keysize);
    }

    // ProcessData(out, in, length)
    ECB_Mode<LEA>::Encryption enc(key, keysize);
    enc.ProcessData(encrypted, pt, length);

    ECB_Mode<LEA>::Decryption dec(key, keysize);
    dec.ProcessData(decrypted, encrypted, length);

    print_result("LEA_256_ECB", encrypted, decrypted, length);
}

void lea_cbc_sample(bool useRandomKeyAndIv) 
{
    const size_t keysize = 32;
    const size_t length = 32;
    uint8_t key[keysize] = { 0 };
    uint8_t iv[16] = { 0 };
    uint8_t pt[length] = { 0 };    
    uint8_t encrypted[length] = { 0 };
    uint8_t decrypted[length] = { 0 };
    
    if (useRandomKeyAndIv) {
        randomize(key, keysize, iv, 16);
    }

    CBC_Mode<LEA>::Encryption enc(key, keysize, iv);
    enc.ProcessData(encrypted, pt, length);

    CBC_Mode<LEA>::Decryption dec(key, keysize, iv);
    dec.ProcessData(decrypted, encrypted, length);    

    print_result("LEA_256_CBC", encrypted, decrypted, length);
}

void lea_cfb_sample(bool useRandomKeyAndIv) 
{
    const size_t keysize = 32;
    const size_t length = 33;
    uint8_t key[keysize] = { 0 };
    uint8_t iv[16] = { 0 };
    uint8_t pt[length] = { 0 };    
    uint8_t encrypted[length] = { 0 };
    uint8_t decrypted[length] = { 0 };
    
    if (useRandomKeyAndIv) {
        randomize(key, keysize, iv, 16);
    }

    CFB_Mode<LEA>::Encryption enc(key, keysize, iv);
    enc.ProcessData(encrypted, pt, length);

    CFB_Mode<LEA>::Decryption dec(key, keysize, iv);
    dec.ProcessData(decrypted, encrypted, length);    

    print_result("LEA_256_CFB", encrypted, decrypted, length);
}

void lea_ofb_sample(bool useRandomKeyAndIv) 
{
    const size_t keysize = 32;
    const size_t length = 33;
    uint8_t key[keysize] = { 0 };
    uint8_t iv[16] = { 0 };
    uint8_t pt[length] = { 0 };    
    uint8_t encrypted[length] = { 0 };
    uint8_t decrypted[length] = { 0 };
    
    if (useRandomKeyAndIv) {
        randomize(key, keysize, iv, 16);
    }

    OFB_Mode<LEA>::Encryption enc(key, keysize, iv);
    enc.ProcessData(encrypted, pt, length);

    OFB_Mode<LEA>::Decryption dec(key, keysize, iv);
    dec.ProcessData(decrypted, encrypted, length);    

    print_result("LEA_256_OFB", encrypted, decrypted, length);
}

void lea_ctr_sample(bool useRandomKeyAndIv) 
{
    const size_t keysize = 32;
    const size_t length = 33;
    uint8_t key[keysize] = { 0 };
    uint8_t ctr[16] = { 0 };
    uint8_t pt[length] = { 0 };    
    uint8_t encrypted[length] = { 0 };
    uint8_t decrypted[length] = { 0 };
    
    if (useRandomKeyAndIv) {
        randomize(key, keysize, ctr, 16);
    }

    CTR_Mode<LEA>::Encryption enc(key, keysize, ctr);
    enc.ProcessData(encrypted, pt, length);

    CTR_Mode<LEA>::Decryption dec(key, keysize, ctr);
    dec.ProcessData(decrypted, encrypted, length);    

    print_result("LEA_256_CTR", encrypted, decrypted, length);
}

void lea_gcm_sample()
{
    const size_t keylen = 32;
	const size_t msglen = 32;
	const size_t ivlen = 16;
	const size_t aadlen = 16;
	const size_t taglen = 16;

	uint8_t key[keylen] = { 0, };
	uint8_t iv[ivlen] = { 0, };

	uint8_t pt[msglen] = { 0, };		
	uint8_t encrypted[msglen] = { 0, };
	uint8_t decrypted[msglen] = { 0, };
	uint8_t tag[taglen] = { 0, };
	uint8_t aad[aadlen] = { 0, };

    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(key, keylen);
    rnd.GenerateBlock(iv, ivlen);
    rnd.GenerateBlock(aad, aadlen);

	GCM<LEA>::Encryption enc;
    enc.SetKeyWithIV(key, keylen, iv, ivlen);	
	enc.EncryptAndAuthenticate(encrypted, tag, taglen, iv, ivlen, aad, aadlen, pt, msglen);

	// if tag changed, verification must be failed
	// OS_GenerateRandomBlock(false, tag, taglen);

	GCM<LEA>::Decryption dec;
	dec.SetKeyWithIV(key, keylen, iv, ivlen);
	bool verified = dec.DecryptAndVerify(decrypted, tag, taglen, iv, ivlen, aad, aadlen, encrypted, msglen);

    printf("LEA_256_GCM\n");
	print_hex("    pt", pt, msglen);
	print_hex("    ct", encrypted, msglen);
    print_hex("   aad", aad, aadlen);
	print_hex("   tag", tag, taglen);

	print_hex("   dec", decrypted, msglen);
	printf   ("   verified: %s\n", verified ? "true" : "false");
}

int main() 
{
    lea_ecb_sample(false);
    lea_cbc_sample(false);
    lea_cfb_sample(false);
    lea_ofb_sample(false);
    lea_ctr_sample(false);
    
    lea_gcm_sample();

    return 0;
}