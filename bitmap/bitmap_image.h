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

#include <cstdint>

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint32_t filesize;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset;
} BitmapFileHeader;

typedef struct __attribute__((packed)) {
    uint32_t headersize;
    uint32_t width;
    uint32_t height;
    uint16_t countColorPlanes;
    uint16_t bitsPerPixel;
    uint32_t compressionMethod;
    uint32_t imageSize;
    uint32_t horizontalResolution;
    uint32_t verticalResolution;
    uint32_t countColors;
    uint32_t countImportantColors;
} BitmapInfoHeader;

class BitmapImage {
    private:
        BitmapFileHeader fileHeader;
        BitmapInfoHeader infoHeader;
        uint8_t* rawData;

    public:
        BitmapImage();
        ~BitmapImage();

        void load(const char* filepath);
        void save(const char* filepath);

        uint8_t* data();
        uint32_t datasize() const;
        void printInfo() const;

        static BitmapImage diff(const BitmapImage& lhs, const BitmapImage& rhs);
};
