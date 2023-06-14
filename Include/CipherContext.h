#pragma once
#include <sodium.h>
#include "tsmap.h"

using namespace std;

namespace crypto {
	class CipherContext {
	public:
		CipherContext();
		CipherContext(unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES]);
		void GenerateKey();
		bool SetKey(const string&);
		string Encrypt(string&&);
		string Decrypt(string&&);
	private:
		unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
		unique_ptr<tsmap<string, bool>> replay;
	};
}