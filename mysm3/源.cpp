#include "mysm3.h"
#include<openssl/evp.h>
#include <ctime>
using namespace std;

const int SIZE = 0xfffff;

void sm3(char* message, unsigned int length, unsigned char* hash, unsigned int* hash_length)
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

int main()
{
	char* x = new char[1];
	x[0] = 'A';
	
	word* h = new word[8];
	unsigned char* h1 = new unsigned char[32];
	unsigned int hal;

	clock_t start1 = clock();
	for (int i = 0; i < SIZE; i++)
		sm3(x, 1, h1, &hal);
	clock_t end1 = clock();

	clock_t start = clock();
	for (int i = 0; i < SIZE; i++)
		h = simple_sm3(x,1);
	clock_t end = clock();
	
	
	cout << "times: " << SIZE << endl;
	cout << "from my_sm3: " << (double)(end - start) / CLOCKS_PER_SEC << " s" << endl;
	cout << "from openssl: " << (double)(end1 - start1) / CLOCKS_PER_SEC << " s" << endl;
	cout << "ratio: " << (double)(end - start) / (double)(end1 - start1)<<endl;

	char y[1] = { 'B' };
	word* h_prime = new word[8];
	h_prime=simple_sm3(y, 1,1,h);
	cout << "Hash of (A+padding)||B = ";
	for (int i = 0; i < 8; i++)
		cout << hex << h_prime[i] << " ";
}