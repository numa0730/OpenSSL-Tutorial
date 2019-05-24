// GenPrivateKey.cpp : パスワードを使った暗号化 (Password Based Encryption)
//           PKCS#5-PBKDF2, SHA256

#include <cstdio>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main()
{
	OpenSSL_add_all_algorithms();

	// ---------------------------------------------------------------------------
	// Derives private key from password (PKCS#5)
	// ---------------------------------------------------------------------------
	const char* pass = "password";
	int iterations = 10000; // as of 2019, should be higher than 10,000
	unsigned char salt[16]; // random for protecting from directional attack
	RAND_bytes(salt, 16);

	unsigned char privatekey[16]; // derived private key, 16byte=128bit

	if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, sizeof(salt) / sizeof(unsigned char), iterations, EVP_sha256(), 16, privatekey) == 1) // RFC2898
	{
		char hexout[16 * 2 + 1];
		for (unsigned int i = 0; i < 16; ++i)
		{
			sprintf_s(&hexout[i * 2], 3, "%02x", 0xFF & privatekey[i]);
		}
		hexout[16 * 2] = '\0';
		printf(hexout);

		OPENSSL_cleanse(hexout, sizeof(privatekey));
		OPENSSL_cleanse(hexout, sizeof(hexout));
	}

	// ---------------------------------------------------------------------------
	// Generate private key automatically
	// ---------------------------------------------------------------------------
	RAND_bytes(privatekey, 16);

	// ---------------------------------------------------------------------------
	// Secure way to store private key (PKCS#8)
	// ---------------------------------------------------------------------------

	/*
	if (EVP_CIPHER_CTX_init(&c))
	{
		EVP_EncryptInit(&c, EVP_aes_128_ecb(), password, nullptr);
		EVP_EncryptUpdate(&context, encrypt.data(), &len, message,
			static_cast<int>(str.length() + EVP_MAX_BLOCK_LENGTH));
		EVP_EncryptFinal(&context, encrypt.data() + len, &len);

		EVP_CIPHER_CTX_cleanup(&c); // erase EVP_CIPHER_CTX
	}
	*/



	return 0;
}
