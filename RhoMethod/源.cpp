//空间复杂度为O1
#include<iostream>
#include"string.h"
#include"openssl/evp.h"
#include<ctime>
using namespace std;

const int collosion_size = 3;//24bit


void sm3(unsigned char* message, unsigned int length, unsigned char* hash, unsigned int* hash_length)
{
	const EVP_MD* md;
	EVP_MD_CTX* md_ctx;
	md = EVP_sm3();
	md_ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, message, length);
	EVP_DigestFinal_ex(md_ctx, hash, hash_length);
	EVP_MD_CTX_free(md_ctx);
}

void double_sm3(unsigned char* message, unsigned int length, unsigned char* hash, unsigned int* hash_length)
{
	sm3(message,length, hash, hash_length);
	sm3(hash, *hash_length, message, hash_length);
}

inline bool isEqual(unsigned char* message1,unsigned char* message2)
{
	for (int i = 0; i < collosion_size; i++)
	{
		if (message1[i] != message2[i])
			return false;
	}
	return true;
}


int main()
{
	srand(unsigned(time(NULL)));
	unsigned char* temp = new unsigned char[32];
	unsigned char* temp1 = new unsigned char[32];
	unsigned int hash_length1 = 32;
	unsigned int hash_length2 = 32;
	unsigned char* message = new unsigned char[32];
	unsigned char* message1 = new unsigned char[32];
	for (int i = 0; i < 32; i++)
	{
		message[i] = (unsigned char)(rand() % 94 + 32);//可打印字符
		message1[i] = message[i];
	}

	clock_t start = clock();	
	for (;;)
	{
		for (int i = 0; i < 32; i++)
			temp1[i] = message1[i];
		sm3(message1, 32, message1, &hash_length1);
		double_sm3(message, 32, temp, &hash_length2);
		
		if (isEqual(message, message1))
		{
			clock_t end = clock();
			cout << "Part hash value of ";
			for (int j = 0; j < 32; j++)
				cout << hex << (int)temp[j];
			cout << " = ";
			for (int j = 0; j < collosion_size; j++)
				cout << hex << (int)message[j];
			cout << endl;
			cout << "Part hash value of ";
			for (int j = 0; j < 32; j++)
				cout << hex << (int)temp1[j];
			cout << " = ";
			for (int j = 0; j < collosion_size; j++)
				cout << hex << (int)message1[j];
			cout << endl;
			cout << (double)(end - start) / CLOCKS_PER_SEC << 's' << endl;
			cout << "collosion_size = " <<dec<<(collosion_size*8)<<" bits";
			return 0;
		}
	}
}