#pragma once
#include <stdint.h>

typedef enum {
	SECURITY_AES
}SECURITY_TYPE;

class CSecurity
{
public:
	CSecurity();
	~CSecurity();

public:
	//memory
	int security(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen);
	int parsing(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen);

	//file
	int file_security(int type, const char *inPath, const char *outPath, const char *key);
	int file_parsing(int type, const char *inPath, const char *outPath, const char *key);

	//files to memory
	int security_memory_to_file(int type, uint8_t *inData, int64_t inLen, uint8_t *key, const char *outPath);
	int parsing_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen);
};