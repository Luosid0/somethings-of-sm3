/*
* 由于技术水平以及优化原因（对，就是又菜又爱玩），对计算长信息摘要的关键函数update做调整；
* 反注释#define normal，则各函数作用与openssl类似；
* 否则，update函数的消息参数应为 64byte的整数倍，并通过init函数中置exattack_flag以实现相似作用；
* 多线程慢上百倍
*/

#include<iostream>
#include<thread>
using namespace std;

//#define normal
typedef unsigned int word;

const word T1 = 0x79cc4519;
const word T2 = 0x7a879d8a;
const word IV[8] = {0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
					0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};

class Mysm3
{
private:
	unsigned long long length;//bit
	int tail;//byte

	word* hash;

	char* data;
	char* buffer;

	static inline word FG(word* x, word* y, word* z);
	static inline word FF(word* x, word* y, word* z);
	static inline word GG(word* x, word* y, word* z);
	static inline word shift(word* x, int k);
	static inline word P1(word* x);
	static inline word P0(word* x);

	void extention(word* list, word* list_prime);
	void compresstion(word* list, word* list_prime);
public:
	Mysm3();
	void init(bool exattck_flag, word* konwnHash);
	void update(char* message,int len);
	word* final();
};

//flag=1 -> length extention attack
word* simple_sm3(char* message,int len, bool exattck_flag = 0, word* konwnHash = NULL)
{
	Mysm3 md = Mysm3();
	md.init(exattck_flag, konwnHash);
	md.update(message,len);
	word* result = md.final();
	return result;
}


inline word Mysm3::FG(word* x, word* y, word* z)
{
	return *x ^ *y ^ *z;
}
inline word Mysm3::FF(word* x, word* y, word* z)
{
	return (*x & *y) | (*y & *z) | (*x & *z);
}
inline word Mysm3::GG(word* x, word* y, word* z)
{
	return (*x & *y) | ((~*x) & *z);
}
inline word Mysm3::shift(word* x, int k)
{
	word t1 = *x >> (32 - k);
	t1 = t1 | (*x << k);
	return t1;
}
inline word Mysm3::P1(word* x)
{
	word t1 = shift(x, 15);
	word t = *x ^ (shift(x, 23));
	t = t ^ t1;
	return t;
}
inline word Mysm3::P0(word* x)
{
	word t1 = shift(x, 9);
	word t = *x ^ (shift(x, 17));
	t = t ^ t1;
	return t;
}

Mysm3::Mysm3()
{
	length = 0;
	tail = 0;
	data = NULL;
	hash = new word[8];
	buffer = new char[64];
}

//flag=1 -> length extention attack
void Mysm3::init(bool exattck_flag = 0, word* konwnHash = NULL)
{
	if (!exattck_flag)
	{
		for (int i = 0; i < 8; i++)
			hash[i] = IV[i];
	}
	else
	{
		for (int i = 0; i < 8; i++)
			hash[i] = konwnHash[i];
	}
}

void Mysm3::update(char* message,int len)
{

	word* wlist = new word[68];
	word* wlist_prime = new word[64];
	length += ((unsigned long long)len) << 3;

#ifndef normal
	int blocks = length >> 9;
	data = message;
#endif

#ifdef normal
	for (int i = 0; i < tail; i++)
		buffer[i] = data[i];
	int blocks = 0;


	if (len + tail <= 64)
	{
		for (int i = tail; i < tail + len; i++)
			buffer[i] = message[i - tail];
		data = buffer;
	}
	else
	{
		for (int i = tail; i < 64; i++)
			buffer[i] = message[i - tail];
		data = message + 64 - tail;
		blocks = (len + tail) >> 6;
		blocks -= 1;
		for (int i = 0; i < 64; i += 4)
			wlist[i / 4] = (((word)buffer[i]) << 24) + (((word)buffer[i + 1]) << 16) + (((word)buffer[i + 2]) << 8) + ((word)buffer[i + 3]);
		extention(wlist, wlist_prime);
		compresstion(wlist, wlist_prime);
	}
#endif
	tail = (length % 512)>>3;

	for (int i = 0; i < blocks; i++)
	{
		for (int i = 0; i < 64; i+=4)
			wlist[i/4] = (((word)data[i]) << 24) + (((word)data[i + 1]) << 16) + ((((word)data[i + 2]) << 8) + ((word)data[i + 3]));
		data += 64;
		extention(wlist, wlist_prime);
		compresstion(wlist, wlist_prime);
	}
}

word* Mysm3::final()
{
	word* wlist = new word[68];
	word* wlist_prime = new word[64];
	int temp = tail / 4;
	int temp1 = tail % 4;
	for (int i = 0; i < 64; i += 4)
		wlist[i / 4] = (((word)data[i]) << 24) + (((word)data[i + 1]) << 16) + (((word)data[i + 2]) << 8) + ((word)data[i + 3]);
	data += tail-temp1;
	wlist[temp] = 0;
	for (int i = 0; i < temp1; i++)
		wlist[temp] += ((word)data[i]) << ((3-i) * 8);
	wlist[temp] += (0x80 << ((3 - temp1)*8));
	if (tail <= 56)
	{
		for (int i = temp + 1; i < 14; i++)
			wlist[i] = 0;
		wlist[14] = (word)(length>>32);
		wlist[15] = (word)length;
		extention(wlist, wlist_prime);
		compresstion(wlist, wlist_prime);
		return hash;
	}
	else
	{
		for (int i = temp + 1; i < 16; i++)
			wlist[i] = 0;
		extention(wlist, wlist_prime);
		compresstion(wlist, wlist_prime);

		for (int i = 0; i < 14; i++)
			wlist[i] = 0;
		wlist[14] = (word)(length >> 32);
		wlist[15] = (word)length;
		extention(wlist, wlist_prime);
		compresstion(wlist, wlist_prime);
		return hash;
	}
	
}

void Mysm3::extention(word* list,word* list_prime)
{
	
	for (int j = 16; j < 68; j+=2)//or 64bit SIMD
	{
		word temp2 = shift(list + j - 2, 15);
		word temp = shift(list + j - 3, 15);
		word temp3 = shift(list + j - 12, 7);
		word temp1 = shift(list + j - 13, 7);
		temp = temp ^ (list[j - 16] ^ list[j - 9]);
		temp2 = temp2 ^ (list[j - 15] ^ list[j - 8]);
		temp=P1(&temp);
		temp2 = P1(&temp2);
		temp = temp ^ (temp1 ^ list[j - 6]);
		temp2 = temp2 ^ (temp3 ^ list[j - 5]);
		list[j] = temp;
		list[j + 1] = temp2;
	}

	for (int j = 0; j < 64; j += 4)//cache line=64Byte
	{
		list_prime[j] = list[j] ^ list[j + 4];
		list_prime[j + 1] = list[j + 1] ^ list[j + 5];
		list_prime[j + 2] = list[j + 2] ^ list[j + 6];
		list_prime[j + 3] = list[j + 3] ^ list[j + 7];
	}
}

void Mysm3::compresstion(word* list, word* list_prime)
{
	
	word* AtoH = new word[8];
	for (int i = 0; i < 8; i++)
		AtoH[i] = hash[i];
	for (int j = 0; j < 16; j++)
	{
		word Ashift12 = shift(AtoH, 12);
		word SS1 = Ashift12 + AtoH[4] + (shift((word*)(&T1), j));
		SS1 = shift(&SS1, 7);
		word SS2 = Ashift12 ^ SS1;
		
		//下面两个模块可并行，可惜创建进程开销更大
		word TT1 = list_prime[j]+SS2+FG(AtoH, AtoH + 1, AtoH + 2) + AtoH[3];
		AtoH[3] = AtoH[2];
		AtoH[2] = shift(AtoH + 1, 9);
		AtoH[1] = AtoH[0];
		AtoH[0] = TT1;
		
		word TT2 = list[j] + SS1+FG(AtoH + 4, AtoH + 5, AtoH + 6) + AtoH[7];
		AtoH[7] = AtoH[6];
		AtoH[6] = shift(AtoH + 5, 19);
		AtoH[5] = AtoH[4];
		AtoH[4] = P0(&TT2);
		
	}
	for (int j = 16; j < 64; j++)
	{
		word Ashift12 = shift(AtoH, 12);
		word SS1 = Ashift12 + AtoH[4] + (shift((word*)(&T2), j));
		SS1 = shift(&SS1, 7);
		word SS2 = Ashift12 ^ SS1;

		word TT1 = list_prime[j] + SS2+FF(AtoH, AtoH + 1, AtoH + 2) + AtoH[3];
		AtoH[3] = AtoH[2];
		AtoH[2] = shift(AtoH + 1, 9);
		AtoH[1] = AtoH[0];
		AtoH[0] = TT1;

		word TT2 = list[j] + SS1 + GG(AtoH + 4, AtoH + 5, AtoH + 6) + AtoH[7];
		AtoH[7] = AtoH[6];
		AtoH[6] = shift(AtoH + 5, 19);
		AtoH[5] = AtoH[4];
		AtoH[4] = P0(&TT2);
	}
	for (int i = 0; i < 8; i++)
		hash[i] = AtoH[i]^hash[i];
}



