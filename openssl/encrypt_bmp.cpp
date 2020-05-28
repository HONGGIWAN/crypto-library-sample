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

#include "../bitmap/bitmap_image.h"

#include <cstring>

#include <openssl/aes.h>
#include <openssl/modes.h>

void encrypt_ecb(BitmapImage& bmp, const uint8_t* mk)
{
    auto data = bmp.data();
    auto length = bmp.datasize();

    AES_KEY key;
    AES_set_encrypt_key(mk, 256, &key);

    while (length >= 16) {
        AES_ecb_encrypt(data, data, &key, AES_ENCRYPT);

        data += 16;
        length -= 16;
    }
}

void encrypt_ctr(BitmapImage& bmp, const uint8_t* mk, const uint8_t* iv)
{
    unsigned int num = 0;
    uint8_t ctr[16] = {0};
    uint8_t ectr[16] = {0};

    memcpy(ctr, iv, 16);

    auto data = bmp.data();
    auto length = bmp.datasize();

    AES_KEY key;
    AES_set_encrypt_key(mk, 256, &key);

    CRYPTO_ctr128_encrypt(data, data, length, &key, ctr, ectr, &num, (block128_f)AES_encrypt);
}

int main(int argc, const char** argv)
{
    uint8_t mk[32] = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    };

    uint8_t iv[16] = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    };

    auto bmp = BitmapImage();
    bmp.load("../samples/ryan.bmp");

    encrypt_ecb(bmp, mk);
    bmp.save("../ryan_ecb.bmp");

    bmp.load("../samples/ryan.bmp");
    encrypt_ctr(bmp, mk, iv);
    bmp.save("../ryan_ctr.bmp");

    auto bmp2 = BitmapImage();
    bmp2.load("../samples/ryan_modified.bmp");

    encrypt_ctr(bmp2, mk, iv);
    bmp2.save("../ryan_modified_ctr.bmp");

    auto diff = BitmapImage::diff(bmp, bmp2);
    diff.save("../ryan_diff.bmp");

    return 0;
}