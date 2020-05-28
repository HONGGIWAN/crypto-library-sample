CC = gcc
CFLAGS = -O2
CXX = g++
CXXFLAGS = -O2
TARGET = openssl_aes openssl_evp openssl_hash openssl_mac openssl_rsa encrypt_bmp
LDFLAGS = -lcrypto

.PHONY: all clean

all : $(TARGET)

openssl_aes:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

openssl_evp:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

openssl_hash:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

openssl_mac:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	
openssl_rsa:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

encrypt_bmp: encrypt_bmp.cpp ../bitmap/bitmap_image.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm $(TARGET) -rf
