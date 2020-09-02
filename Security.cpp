#include "Security.h"
#include "encrypt.h"

CSecurity::CSecurity()
{
}
CSecurity::~CSecurity()
{
}

int CSecurity::security(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	Cryption encrypt;
	int ret = encrypt.encrypt(type, inData, inLen, key, outData, outLen);

	return ret;
}

int CSecurity::parsing(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	Cryption decrypt;
	int ret = decrypt.decrypt(type, inData, inLen, key, outData, outLen);

	return ret;
}


int CSecurity::file_security(int type, const char *inPath, const char *outPath, const char *key)
{
	Cryption encrypt;
	int ret = encrypt.encrypt_file(type, inPath, outPath, key);

	return ret;
}

int CSecurity::file_parsing(int type, const char *inPath, const char *outPath, const char *key)
{
	Cryption decrypt;
	int ret = decrypt.decrypt_file(type, inPath, outPath, key);

	return ret;
}

int CSecurity::security_memory_to_file(int type, uint8_t *inData, int64_t inLen, uint8_t *key, const char *outPath)
{
	Cryption encrypt;
	int ret = encrypt.encrypt_memory_to_file(type, inData, inLen, key, outPath);

	return ret;
}
int CSecurity::parsing_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	Cryption decrypt;
	int ret = decrypt.decrypt_file_to_memory(type, inPath, key, outData, outLen);

	return ret;
}
