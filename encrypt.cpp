#include "rijndael.h"
#include "encrypt.h"

#include <fstream>
#include <assert.h>

typedef enum {
	ENCRYPT,
	DECRYPT,
}AES_CRYPT_TYPE;

#define KEY  "qwertyuiopasdfghjklzxcvbnm123456"//32
#define IV   "1234567812345678"//16
#define CHECK_CODE "gaoding"//check code. this should change with the CHECK_CODE_LEN
#define CHECK_CODE_LEN (7)
#define AES_PLAINTEXT_LEN (16)//don't change


static void getSpecificationKey(AES_CYPHER_T mode, uint8_t *key, uint8_t *skey)
{
	const int KEY_LEN = (mode + 2) * 8;

	if (key == NULL)
	{
		memcpy(skey, KEY, KEY_LEN);//Default key
	}
	else
	{
		int keylen = strlen((char*)key);
		if (keylen > KEY_LEN)//Password is too long 
		{
			memcpy(skey, key, KEY_LEN);
		}
		else
		{
			memcpy(skey, key, keylen);
			memcpy(skey + keylen, KEY, KEY_LEN - keylen);
		}
	}
}
//--------------------------------------------------------------------
static int _aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int64_t len, uint8_t *key, uint8_t *iv)
{
//The key must be 16 or 24 or 32 bits;
//The plaintext must be a curb of 16 or 24 or 32. If the input is not a multiple of 16, 
//win32 and win64 platforms will get different results;
//It is recommended that if the plaintext is not a multiple of 16, complete it yourself;

	int64_t pLen = len;
	uint8_t *pin = data;
	while (pLen >= AES_PLAINTEXT_LEN)
	{
		uint8_t buffer[AES_PLAINTEXT_LEN + 1] = { 0 };
		memcpy(buffer, pin, AES_PLAINTEXT_LEN);
		aes_encrypt_cbc(mode, buffer, AES_PLAINTEXT_LEN, key, iv);//encrypt
		memcpy(pin, buffer, AES_PLAINTEXT_LEN);

		pin += AES_PLAINTEXT_LEN;
		pLen -= AES_PLAINTEXT_LEN;
	}

	assert(pLen < AES_PLAINTEXT_LEN);
	//the last 16 bytes
	{
		uint8_t buffer[AES_PLAINTEXT_LEN + 1] = { 0 };
		memcpy(buffer, pin, pLen);

		for (int i = 0; i < AES_PLAINTEXT_LEN - pLen; ++i)
		{
			buffer[pLen + i] = uint8_t(AES_PLAINTEXT_LEN - pLen);
		}

		aes_encrypt_cbc(mode, buffer, AES_PLAINTEXT_LEN, key, iv);//encrypt
		memcpy(pin, buffer, AES_PLAINTEXT_LEN);

		return len + AES_PLAINTEXT_LEN - pLen;
	}
}

static int _aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int64_t len, uint8_t *key, uint8_t *iv)
{
	uint8_t *pin = data;
	int64_t pLen = len;
	while (pLen > AES_PLAINTEXT_LEN)
	{
		uint8_t buffer[AES_PLAINTEXT_LEN + 1] = { 0 };
		memcpy(buffer, pin, AES_PLAINTEXT_LEN);

		aes_decrypt_cbc(mode, buffer, AES_PLAINTEXT_LEN, key, iv);//decrypt

		memcpy(pin, buffer, AES_PLAINTEXT_LEN);
		pin += AES_PLAINTEXT_LEN;
		pLen -= AES_PLAINTEXT_LEN;
	}

	assert(pLen == AES_PLAINTEXT_LEN);
	//the last 16 bytes
	{
		uint8_t buffer[AES_PLAINTEXT_LEN + 1] = { 0 };
		memcpy(buffer, pin, pLen);

		aes_decrypt_cbc(mode, buffer, AES_PLAINTEXT_LEN, key, iv);//decrypt

		int nLast = (int)buffer[AES_PLAINTEXT_LEN - 1];
		memcpy(pin, buffer, AES_PLAINTEXT_LEN - nLast);
		pin += (AES_PLAINTEXT_LEN - nLast);
		pin[0] = '\0';

		return len - nLast;
	}
}

static int64_t interface_cryption(AES_CRYPT_TYPE type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData)
{
	uint8_t skey[33] = { 0 };
	getSpecificationKey(AES_CYPHER_256, key, skey);

	int64_t newLen = inLen + CHECK_CODE_LEN + 17;
	uint8_t *buffer = (uint8_t*)malloc(newLen * sizeof(char));
	memset(buffer, 0, newLen * sizeof(char));
	memcpy(buffer, inData, inLen);
	
	int64_t retLen = 0;
	if (type == ENCRYPT)
	{
		//add check code
		memcpy(buffer + inLen, CHECK_CODE, CHECK_CODE_LEN);

		retLen = _aes_encrypt_cbc(AES_CYPHER_256, buffer, inLen + CHECK_CODE_LEN, skey, (uint8_t*)IV);//encrypt
		if (retLen > 0)
		{
			*outData = (uint8_t*)malloc((retLen + 1) * sizeof(char));
			memcpy(*outData, buffer, retLen);
			*(*outData + retLen) = '\0';
		}
	}
	else if (type == DECRYPT)
	{
		retLen = _aes_decrypt_cbc(AES_CYPHER_256, buffer, inLen, skey, (uint8_t*)IV);//decrypt
		if (retLen > 0)
		{
			char check_buffer[CHECK_CODE_LEN + 1] = { 0 };
			memcpy(check_buffer, buffer + retLen - CHECK_CODE_LEN, CHECK_CODE_LEN);
			if (0 == strcmp(CHECK_CODE, check_buffer))
			{	
				//remove check code, and assignment to outData
				*outData = (uint8_t*)malloc((retLen - CHECK_CODE_LEN + 1) * sizeof(char));
				memcpy(*outData, buffer, retLen - CHECK_CODE_LEN);
				*(*outData + retLen - CHECK_CODE_LEN) = '\0';
				retLen -= CHECK_CODE_LEN;
			}
			else
			{
				//wrong password or decrypt error
				retLen = 0;
			}
		}
	}
	
	free(buffer);
	buffer = nullptr;

	return retLen;
}
//-------------------------------------------------------------------
static bool interface_cryption_file(AES_CRYPT_TYPE type, const char *inPath, const char *outPath, const char *key)
{
	FILE *inFile, *outFile;
	uint8_t *inBuffer = nullptr, *outBuffer = nullptr;
	int64_t filesize;
	int64_t outFileSize;

	if ((inFile = fopen(inPath, "rb")) == NULL) 
	{
		//printf("open file failed /n");
		return false;
	}

	fseek(inFile, 0, SEEK_END);
	filesize = ftell(inFile);

	inBuffer = (uint8_t*)malloc(filesize + 1);
	memset(inBuffer, 0, (filesize + 1) * sizeof(char));

	fseek(inFile, 0, SEEK_SET);
	fread(inBuffer, 1, filesize, inFile);
	fclose(inFile);

	outFileSize = interface_cryption(type, inBuffer, filesize, (uint8_t*)key, &outBuffer);

	if (outFileSize == 0)
	{
		//printf("encrypt failed /n");
		free(inBuffer);
		inBuffer = nullptr;
		return false;
	}

	if ((outFile = fopen(outPath, "wb")) == NULL) 
	{
		printf("open file failed /n");
		free(inBuffer);
		inBuffer = nullptr;
		free(outBuffer);
		outBuffer = nullptr;
		return false;
	}

	fwrite(outBuffer, 1, outFileSize, outFile);
	fclose(outFile);

	free(inBuffer);
	inBuffer = nullptr;
	free(outBuffer);
	outBuffer = nullptr;

	return true;
}

//-----------------------------class Cryption------------------------
Cryption::Cryption()
{
}

Cryption::~Cryption()
{
}

//memory
int Cryption::encrypt(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	*outLen = interface_cryption(ENCRYPT, inData, inLen, key, outData);
	return (*outLen > 0) ? 1 : 0;
}

int Cryption::decrypt(int type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	*outLen = interface_cryption(DECRYPT, inData, inLen, key, outData);
	return (*outLen > 0) ? 1 : 0;
}

//file
int Cryption::encrypt_file(int type, const char *inPath, const char *outPath, const char *key)
{
	bool ret = interface_cryption_file(ENCRYPT, inPath, outPath, key);
	return (ret) ? 1 : 0;
}

int Cryption::decrypt_file(int type, const char *inPath, const char *outPath, const char *key)
{
	bool ret = interface_cryption_file(DECRYPT, inPath, outPath, key);
	return (ret) ? 1 : 0;
}

//memory - file
int Cryption::encrypt_memory_to_file(int type, uint8_t *inData, int64_t inLen, uint8_t *key, const char *outPath)
{
	uint8_t *outData = nullptr;
	int64_t outLen;

	outLen = interface_cryption(ENCRYPT, inData, inLen, key, &outData);
	if (outLen <= 0)
		return 0;

	FILE *File = nullptr;
	File = fopen(outPath, "wb");
	if (File == NULL)
		return 0;

	fwrite(outData, 1, outLen, File);
	fclose(File);

	return 1;
}

int Cryption::decrypt_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	FILE *File = nullptr;
	uint8_t *inBuffer = nullptr;
	int64_t filesize;

	if ((File = fopen(inPath, "rb")) == NULL)
		return 0;

	fseek(File, 0, SEEK_END);
	filesize = ftell(File);
	inBuffer = (uint8_t*)malloc(filesize + 1);
	memset(inBuffer, 0, (filesize + 1) * sizeof(char));
	fseek(File, 0, SEEK_SET);
	fread(inBuffer, 1, filesize, File);
	fclose(File);

	Cryption decrypt;
	decrypt.decrypt(ENCRYPT, inBuffer, filesize, NULL, outData, outLen);

	return 1;
}