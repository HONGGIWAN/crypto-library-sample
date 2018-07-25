CC = gcc
TARGET = openssl_aes openssl_evp openssl_hash openssl_mac openssl_rsa

.PHONY: all clean

all : $(TARGET)

openssl_aes:
	$(CC) $@.c -o $@ -lcrypto

openssl_evp:
	$(CC) $@.c -o $@ -lcrypto

openssl_hash:
	$(CC) $@.c -o $@ -lcrypto

openssl_mac:
	$(CC) $@.c -o $@ -lcrypto
	
openssl_rsa:
	$(CC) $@.c -o $@ -lcrypto

clean:
	rm $(TARGET) -rf
