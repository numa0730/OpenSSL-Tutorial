// Hash.cpp : ハッシュ関数
//

#include <iostream>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

int main()
{
	OpenSSL_add_all_digests();

	
	// SHA-2 Hash Test
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH];
	if (SHA256_Init(&c))
	{
		SHA256_Update(&c, (void*)"password", 8);
		SHA256_Final(md, &c);
		memset(&c, 0, sizeof(SHA_CTX)); // erase SHA_CTX
		printf("SHA-256 of \"password\" is \n");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		{
			printf("%.2x", md[i]);
		}
		printf("\n");
	}

	// SHA-1 Hash with Salt 
	unsigned char rand[4]; // 4bytes is only for sample. Should be longer than 128 bits for safety. 
	RAND_bytes(rand, 4);
	
	const uint32_t* pVal = (uint32_t*)&rand[0];
	if (SHA256_Init(&c))
	{
		SHA256_Update(&c, (void*)rand, 4);
		SHA256_Update(&c, (void*)"password", 8);
		SHA256_Final(md, &c);
		memset(&c, 0, sizeof(SHA_CTX)); // erase SHA_CTX
		printf("SHA-256 of \"password\" with salt(%.8x) is \n", *pVal);
		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		{
			printf("%.2x", md[i]);
		}
		printf("\n");
	}

	return 0;
}
