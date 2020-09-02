#pragma once

typedef enum {
	AES
}CRYPT_TYPE;

class Cryption
{
public:
	Cryption();
	~Cryption();

public:
	//memory
	int encrypt(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen);
	int decrypt(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen);

	//file
	int encrypt_file(int type, const char *inPath, const char *outPath, const char *key);
	int decrypt_file(int type, const char *inPath, const char *outPath, const char *key);

	//memory - file
	int encrypt_memory_to_file(int type, uint8_t *inData, int64_t inLen, uint8_t *key, const char *outPath);
	int decrypt_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen);
};