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
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "../print_hex.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void CheckError(int state) {
    if (!state) {
        printf("State: %d\n", state);
        handleErrors();
    }
}

void generate_rsa_keys(EVP_PKEY* priKey, EVP_PKEY* pubKey)
{
    BIGNUM* e = BN_new();
    RSA* rsa = RSA_new();

    BN_hex2bn(&e, "010001");
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    CheckError(EVP_PKEY_assign_RSA(priKey, RSAPrivateKey_dup(rsa)));
    CheckError(EVP_PKEY_assign_RSA(pubKey, RSAPublicKey_dup(rsa)));
}

void rsa_encrypt(uint8_t* encrypted, const uint8_t* pt, size_t ptlen, EVP_PKEY* pubkey)
{
    EVP_PKEY_CTX *ctx;
    ENGINE *eng = NULL;
    size_t enclen;
    
    ctx = EVP_PKEY_CTX_new(pubkey, eng);
    if (!ctx) {
        handleErrors();
    }
        
    CheckError(EVP_PKEY_encrypt_init(ctx));        
    CheckError(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    CheckError(EVP_PKEY_encrypt(ctx, NULL, &enclen, pt, ptlen));
    CheckError(EVP_PKEY_encrypt(ctx, encrypted, &enclen, pt, ptlen));

    EVP_PKEY_CTX_free(ctx);
}

void rsa_decrypt(uint8_t* decrypted, const uint8_t* ct, size_t ctlen, EVP_PKEY* prikey) 
{
    EVP_PKEY_CTX *ctx;
    ENGINE *eng = NULL;
    size_t declen;
    
    ctx = EVP_PKEY_CTX_new(prikey, eng);
    if (!ctx) {
        handleErrors();
    }
        
    CheckError(EVP_PKEY_decrypt_init(ctx));        
    CheckError(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    CheckError(EVP_PKEY_decrypt(ctx, NULL, &declen, ct, ctlen));
    CheckError(EVP_PKEY_decrypt(ctx, decrypted, &declen, ct, ctlen));

    EVP_PKEY_CTX_free(ctx);
}

int envelope_seal(EVP_PKEY **pub_key, const uint8_t* plaintext, size_t plaintext_len,
	uint8_t **encrypted_key, int *encrypted_key_len, uint8_t* iv,
	uint8_t* ciphertext)
{
    int len;
	int ciphertext_len;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handleErrors();
    }

	CheckError(EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1));
	CheckError(EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
	ciphertext_len = len;
	
	CheckError(EVP_SealFinal(ctx, ciphertext + len, &len));
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int envelope_open(EVP_PKEY *priv_key, const uint8_t* ciphertext, size_t ciphertext_len,
	const uint8_t* encrypted_key, size_t encrypted_key_len, const uint8_t* iv,
	uint8_t* plaintext)
{
	int len = 0;
	int plaintext_len = 0;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
        handleErrors();
    }
	
	CheckError(EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, priv_key));
	CheckError(EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));		
	plaintext_len = len;

	CheckError(EVP_OpenFinal(ctx, plaintext + len, &len));
	plaintext_len += len;
	
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void sign(EVP_PKEY* key, const uint8_t* msg, size_t msg_length, uint8_t* sig, size_t* slen)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        handleErrors();
    }

    CheckError(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key));
    CheckError(EVP_DigestSignUpdate(ctx, msg, msg_length));
    CheckError(EVP_DigestSignFinal(ctx, NULL, slen));
    CheckError(EVP_DigestSignFinal(ctx, sig, slen));

    EVP_MD_CTX_free(ctx);
}

void verify(EVP_PKEY* key, const uint8_t* msg, size_t msg_length, uint8_t* sig, size_t slen)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        handleErrors();
    }

    CheckError(EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key));
    CheckError(EVP_DigestVerifyUpdate(ctx, msg, msg_length));    
    CheckError(EVP_DigestVerifyFinal(ctx, sig, slen));

    EVP_MD_CTX_free(ctx);
}

void test_encrypt()
{
    uint8_t pt[48] = {1, };
    uint8_t enc[512] = {0 };
    uint8_t dec[512] = {0,};

    EVP_PKEY *priKey = EVP_PKEY_new();
    EVP_PKEY *pubKey = EVP_PKEY_new();
    generate_rsa_keys(priKey, pubKey);

    rsa_encrypt(enc, pt, 48, pubKey);
    rsa_decrypt(dec, enc, 256, priKey);

    print_title("Test RSA Encrypt/Decrypt");
    print_hex_multiline("enc", enc, 256);
    print_hex_multiline("dec", dec, 48);
    print_hex_multiline("pt", pt, 48);
}

void test_seal()
{
    uint8_t pt[48] = {0};
    uint8_t iv[16] = {0};
    uint8_t working_iv[16] = {0};
    uint8_t *ek = NULL;
    uint8_t encrypted[256] = {0};
    uint8_t decrypted[256] = {1};
    
    size_t ptlen = 48;
    size_t enclen, declen;
    int eklen = 1024;    

    EVP_PKEY *priKey = EVP_PKEY_new();
    EVP_PKEY *pubKey = EVP_PKEY_new();
    generate_rsa_keys(priKey, pubKey);

    printf("key size: %d\n", EVP_PKEY_size(pubKey));

    // key and iv are randomly generated
    ek = malloc(EVP_PKEY_size(pubKey));    
    enclen = envelope_seal(&pubKey, pt, ptlen, &ek, &eklen, iv, encrypted);
    declen = envelope_open(priKey, encrypted, enclen, ek, eklen, iv, decrypted);

    print_title("Test Seal");
    
    print_hex_multiline("pt", pt, ptlen);
    print_hex_multiline("iv", iv, 16);

    print_hex_multiline("enc", encrypted, enclen);
    print_hex_multiline("dec", decrypted, declen);

    free(ek);
}

void test_sign()
{
    OpenSSL_add_all_algorithms();

    uint8_t sig[2048] = {0};
    size_t slen = 0;

    EVP_PKEY *priKey = EVP_PKEY_new();
    EVP_PKEY *pubKey = EVP_PKEY_new();
    generate_rsa_keys(priKey, pubKey);
    sign(priKey, "abcde", 5, sig, &slen);
    verify(pubKey, "abcde", 5, sig, slen);

    print_title("Test RSA Signature");
    print_hex_multiline("SIGN", sig, slen);
}

int main()
{
    test_encrypt();
    test_seal();
    test_sign();

    return 0;
}