
#include <iostream>
#include "encrypt.h"
#include "Security.h"

#define MAX_PATH_SIZE 512
void test_security();
void test_encrypt(const char *path);

//----------------encrypt tool-----------------
void encrypt_tool(const char*path)
{
	CSecurity security;
	security.file_security(SECURITY_AES, path, path, NULL);
}

int main(int argc, char *argv[])
{
	encrypt_tool(argv[1]);

	//test_security();
	//test_encrypt("C:/Users/ruoshui/Desktop/1/4/4.txt");

	return 1;
}

//---------------------test------------------------------------
void test_encrypt(const char *path)
{
	FILE *inFile;
	uint8_t *inBuffer;
	int64_t filesize;

	if ((inFile = fopen(path, "rb")) == NULL)
	{
		//printf("open file failed /n");
		return;
	}

	fseek(inFile, 0, SEEK_END);
	filesize = ftell(inFile);
	inBuffer = (uint8_t*)malloc(filesize + 17);//ase encryption requires the length to be a multiple of 16 byte, so allocate more memory
	memset(inBuffer, 0, (filesize + 17) * sizeof(char));
	fseek(inFile, 0, SEEK_SET);
	fread(inBuffer, 1, filesize, inFile);
	fclose(inFile);


	uint8_t *outBuffer = nullptr;
	int64_t outsize;
	Cryption crypt;
	crypt.encrypt(AES, inBuffer, filesize, NULL, &outBuffer, &outsize);

	FILE *fp1 = fopen("C:/Users/ruoshui/Desktop/1/4/41.txt", "wb");
	if (fp1 != NULL)
	{
		fwrite(outBuffer, 1, outsize, fp1);
		fclose(fp1);
	}

	uint8_t *outBuffer2 = nullptr;
	int64_t outsize2;
	crypt.decrypt(AES, outBuffer, outsize, NULL, &outBuffer2, &outsize2);

	FILE *fp2 = fopen("C:/Users/ruoshui/Desktop/1/4/42.txt", "wb");
	if (fp2 != NULL)
	{
		fwrite(outBuffer2, 1, outsize2, fp2);
		fclose(fp2);
	}

	getchar();
}

//----------------------------------------------------------------------------
int get_file_data(const char* path, char **outData, int *outLen)
{
	FILE *file = nullptr;

	if ((file = fopen(path, "rb")) == NULL)
		return 0;

	fseek(file, 0, SEEK_END);
	int filesize = ftell(file);
	*outData = (char*)malloc((filesize + 1) * sizeof(char));
	memset(*outData, 0, (filesize + 1) * sizeof(char));
	fseek(file, 0, SEEK_SET);
	fread(*outData, 1, filesize, file);
	fclose(file);

	*outLen = filesize;
	return 1;
}

void test_security()
{
	char inDir[] = "C:/Users/ruoshui/Desktop/1/test";
	char fileName[] = "test";
	char fileSuffix[] = "txt";


	char inPath[MAX_PATH_SIZE];
	sprintf(inPath, "%s/%s.%s", inDir, fileName, fileSuffix);
	char *inBuffer = nullptr;
	int inLen;
	get_file_data(inPath, &inBuffer, &inLen);


	CSecurity security;
	//memory
	char *outBuffer = nullptr, *parBuffer = nullptr;
	int outLen, parLen;
	security.security(SECURITY_AES, (uint8_t*)inBuffer, inLen, NULL, (uint8_t**)&outBuffer, (int64_t*)&outLen);
	security.parsing(SECURITY_AES, (uint8_t*)outBuffer, outLen, NULL, (uint8_t**)&parBuffer, (int64_t*)&parLen);


	//file
	char outPath[MAX_PATH_SIZE];
	char parPath[MAX_PATH_SIZE];
	sprintf(outPath, "%s/%s_file_jiami.%s", inDir, fileName, fileSuffix);
	sprintf(parPath, "%s/%s_file_jiemi.%s", inDir, fileName, fileSuffix);
	security.file_security(SECURITY_AES, inPath, outPath, NULL);
	security.file_parsing(SECURITY_AES, outPath, parPath, NULL);

	//memory - file
	char outPath2[MAX_PATH_SIZE];
	sprintf(outPath2, "%s/%s_file_jiami2.%s", inDir, fileName, fileSuffix);
	char *outBuffer2 = nullptr;
	int outLen2;
	security.security_memory_to_file(SECURITY_AES, (uint8_t*)inBuffer, inLen, NULL, outPath2);
	security.parsing_file_to_memory(SECURITY_AES, outPath2, NULL, (uint8_t**)&outBuffer2, (int64_t*)&outLen2);

	getchar();
}
