//前32bit 碰撞，需要16bit的空间，有1/2的成功性
#include<iostream>
#include"string.h"
#include"openssl/evp.h"
#include<ctime>
using namespace std;

const int collosion_size = 4;//32 bit
const int list_size = 2<<16;//16 bit

inline bool isEqual(unsigned char* list1, unsigned char* list2)
{
	for (int i = 0; i < collosion_size; i++)
	{
		if (list1[i] != list2[i])
			return false;
	}
	return true;
}


void sm3(char* message, unsigned int length, unsigned char* hash, unsigned int* hash_length)
{
	const EVP_MD* md;
	EVP_MD_CTX* md_ctx;
	md = EVP_sm3();
	md_ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, message, length);
	EVP_DigestFinal_ex(md_ctx,hash,hash_length);
	EVP_MD_CTX_free(md_ctx);
}


int main()
{
	srand(unsigned(time(NULL)));
	unsigned int length = 32;
	unsigned int hash_length;

	unsigned char** hash_list = new unsigned char* [list_size];
	for (int i = 0; i < list_size; i++)
		hash_list[i] = new unsigned char[32];
	char** message_list = new char*[list_size];
	for (int i = 0; i < list_size; i++)
		message_list[i] = new char[length];
	for (int i = 0; i < list_size; i++)
		for (int j = 0; j < length; j++)
			message_list[i][j] = (char)(rand() % 94 + 32);//可打印字符
	
	clock_t start = clock();

	for (int i = 0; i < list_size; i++)
	{
		sm3(message_list[i], length, hash_list[i], &hash_length);
		for (int j = 0; j < i; j++)
		{
			if (isEqual(hash_list[j],hash_list[i]))
			{
				clock_t end = clock();
				cout << "Part hash value of ";
				for (int k = 0; k < length; k++)
					cout<<message_list[i][k];
				cout << " = ";
				for (int k = 0; k < collosion_size; k++)
					cout << hex << (int)hash_list[i][k];
				cout <<endl;
				cout << "Part hash value of ";
				for (int k = 0; k < length; k++)
					cout<<message_list[j][k];
				cout << " = ";
				for (int k = 0; k < collosion_size; k++)
					cout << hex << (int)hash_list[j][k];
				cout << endl;
				cout << (double)(end - start) / CLOCKS_PER_SEC<<'s'<<endl;
				cout << "collion_size = " <<dec<<collosion_size*8<<" bits";
				return 0;
			}
		}
	}
	return 0;
}

