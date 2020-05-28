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

#include "bitmap_image.h"
#include <fstream>
#include <iostream>

static constexpr size_t FileHeaderSize = 14;

BitmapImage::BitmapImage() : rawData(nullptr) 
{}

BitmapImage::~BitmapImage()
{
    if (rawData != nullptr) {
        delete[] rawData;
        rawData = nullptr;
    }
}

void BitmapImage::load(const char* filepath)
{
    auto ifs = std::ifstream();
    ifs.open(filepath, std::ios::binary);

    if (!ifs.is_open()) {
        std::cout << "failed to load " << filepath << std::endl;
        return;
    }

    ifs.read(reinterpret_cast<char*>(&fileHeader), FileHeaderSize);
    ifs.read(reinterpret_cast<char*>(&infoHeader), fileHeader.offset - FileHeaderSize);
    rawData = new uint8_t[infoHeader.imageSize];
    ifs.read(reinterpret_cast<char*>(rawData), infoHeader.imageSize);

    ifs.close();
}

void BitmapImage::save(const char* filepath)
{
    auto ofs = std::ofstream();
    ofs.open(filepath, std::ios::binary);

    if (!ofs.is_open()) {
        std::cout << "failed to save " << filepath << std::endl;
        return;
    }

    ofs.write(reinterpret_cast<char*>(&fileHeader), FileHeaderSize);
    ofs.write(reinterpret_cast<char*>(&infoHeader), fileHeader.offset - FileHeaderSize);
    ofs.write(reinterpret_cast<char*>(rawData), infoHeader.imageSize);

    ofs.close();
}

uint8_t* BitmapImage::data()
{
    return rawData;
}

uint32_t BitmapImage::datasize() const
{
    return infoHeader.imageSize;
}

void BitmapImage::printInfo() const
{
    std::cout << "   magic: " << fileHeader.magic << std::endl;
    std::cout << "filesize: " << fileHeader.filesize << std::endl;
    std::cout << "  offset: " << fileHeader.offset << std::endl;

    std::cout << "   width: " << infoHeader.width << std::endl;
    std::cout << "  height: " << infoHeader.height << std::endl;
    std::cout << "    size: " << infoHeader.imageSize << std::endl;
}

BitmapImage BitmapImage::diff(const BitmapImage& lhs, const BitmapImage& rhs)
{
    auto diffBmp = BitmapImage();

    if (lhs.infoHeader.imageSize != rhs.infoHeader.imageSize) {
        return diffBmp;
    }

    diffBmp.fileHeader = lhs.fileHeader;
    diffBmp.infoHeader = lhs.infoHeader;

    diffBmp.rawData = new uint8_t[diffBmp.infoHeader.imageSize];

    for (auto i = 0; i < diffBmp.infoHeader.imageSize; ++i) {
        diffBmp.rawData[i] = lhs.rawData[i] - rhs.rawData[i];
    }

    return diffBmp;
}