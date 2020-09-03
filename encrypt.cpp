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
#define ENCRYPT_FLAG "#%$@^&@#"
#define ENCRYPT_FLAG_LEN (9)


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
//-----------------------------------------------------------------------------
static int64_t interface_cryption(AES_CRYPT_TYPE type, uint8_t *inData, int64_t inLen, uint8_t *key, uint8_t **outData)
{
	int IS_ENCRYPT_FLAG = 0;

	uint8_t skey[33] = { 0 };
	getSpecificationKey(AES_CYPHER_256, key, skey);

	int64_t newLen = inLen + CHECK_CODE_LEN + 17;
	uint8_t *buffer = (uint8_t*)malloc(newLen * sizeof(char));
	memset(buffer, 0, newLen * sizeof(char));
	memcpy(buffer, inData, inLen);

	//judge whether it is an encrypted data
	char encrtpt_flag[ENCRYPT_FLAG_LEN + 1] = { 0 };
	memcpy(encrtpt_flag, buffer, ENCRYPT_FLAG_LEN);
	if (0 == strcmp(encrtpt_flag, ENCRYPT_FLAG))
	{
		IS_ENCRYPT_FLAG = 1;
	}
	else
	{
		IS_ENCRYPT_FLAG = 0;
	}

	int64_t retLen = 0;
	if (type == ENCRYPT && IS_ENCRYPT_FLAG == 0)
	{
		//add check code at the end
		memcpy(buffer + inLen, CHECK_CODE, CHECK_CODE_LEN);

		//encrypt data
		retLen = _aes_encrypt_cbc(AES_CYPHER_256, buffer, inLen + CHECK_CODE_LEN, skey, (uint8_t*)IV);
		if (retLen > 0)
		{
			uint8_t *outBuffer = (uint8_t*)malloc((retLen + ENCRYPT_FLAG_LEN + 1) * sizeof(char));
			//add encryption flag first
			memcpy(outBuffer, ENCRYPT_FLAG, ENCRYPT_FLAG_LEN);
			//add encrypted data
			memcpy(outBuffer + ENCRYPT_FLAG_LEN, buffer, retLen);
			outBuffer[ENCRYPT_FLAG_LEN + retLen] = '\0';

			*outData = outBuffer;
			retLen += ENCRYPT_FLAG_LEN;
		}
	}
	else if (type == DECRYPT && IS_ENCRYPT_FLAG == 1)
	{
		//encrypted ENCRYPT_FLAG for identification
		uint8_t *pbegin = buffer + ENCRYPT_FLAG_LEN;
		int64_t actualLen = inLen - ENCRYPT_FLAG_LEN;

		//decrypt data
		retLen = _aes_decrypt_cbc(AES_CYPHER_256, pbegin, actualLen, skey, (uint8_t*)IV);
		if (retLen > 0)
		{
			//is the check value correct
			char check_buffer[CHECK_CODE_LEN + 1] = { 0 };
			memcpy(check_buffer, pbegin + retLen - CHECK_CODE_LEN, CHECK_CODE_LEN);
			if (0 == strcmp(CHECK_CODE, check_buffer))
			{
				//remove check code, and assignment to outData
				actualLen = retLen - CHECK_CODE_LEN;
				uint8_t *outBuffer = (uint8_t*)malloc((actualLen + 1) * sizeof(char));
				memcpy(outBuffer, pbegin, actualLen);
				outBuffer[actualLen] = '\0';

				*outData = outBuffer;
				retLen = actualLen;
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
//-------------------------------------------------------------------
static bool interface_encrypt_memory_to_file(int type, uint8_t *inData, int64_t inLen, uint8_t *key, const char *outPath)
{
	uint8_t *outData = nullptr;
	int64_t outLen;

	outLen = interface_cryption(ENCRYPT, inData, inLen, key, &outData);
	if (outLen <= 0)
		return false;

	FILE *File = nullptr;
	File = fopen(outPath, "wb");
	if (File == NULL)
		return false;

	fwrite(outData, 1, outLen, File);
	fclose(File);

	return true;
}

static bool interface_decrypt_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	FILE *File = nullptr;
	uint8_t *inBuffer = nullptr;
	int64_t filesize;

	if ((File = fopen(inPath, "rb")) == NULL)
		return false;

	fseek(File, 0, SEEK_END);
	filesize = ftell(File);
	inBuffer = (uint8_t*)malloc(filesize + 1);
	memset(inBuffer, 0, (filesize + 1) * sizeof(char));
	fseek(File, 0, SEEK_SET);
	fread(inBuffer, 1, filesize, File);
	fclose(File);

	*outLen = interface_cryption(DECRYPT, inBuffer, filesize, key, outData);
	if (*outLen <= 0)
	{
		*outLen = 0;
		if(*outData)
			free(*outData);
		*outData = nullptr;
	}


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
	bool ret = interface_encrypt_memory_to_file(type, inData, inLen, key, outPath);
	return (ret) ? 1 : 0;
}

int Cryption::decrypt_file_to_memory(int type, const char *inPath, uint8_t *key, uint8_t **outData, int64_t *outLen)
{
	bool ret = interface_decrypt_file_to_memory(type, inPath, key, outData, outLen);
	return (ret) ? 1 : 0;
}