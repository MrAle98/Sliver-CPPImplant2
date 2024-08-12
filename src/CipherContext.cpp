#include "CipherContext.h"
#include <gzip/decompress.hpp>
#include <gzip/compress.hpp>

//TODO nonce check for replay
namespace crypto {
	CipherContext::CipherContext() {
		this->replay = make_unique<tsmap<string, bool>>();
	}
	CipherContext::CipherContext(unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES]) {
		memcpy(this->key, key, crypto_aead_chacha20poly1305_IETF_KEYBYTES);
		this->replay = make_unique<tsmap<string, bool>>();
	}
	
	bool CipherContext::SetKey(const string& key) {
		if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
			return false;
		}
		memcpy(this->key, key.c_str(), crypto_aead_chacha20poly1305_IETF_KEYBYTES);
		return true;
	}
	string CipherContext::Decrypt(string&& in) {
		auto enc_string = std::move(in);
		unsigned char* enc = (unsigned char*)enc_string.c_str();
		auto enc_size = enc_string.size();

		auto nonce_3 = enc;
		enc = &enc[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
		string decrypted;
		decrypted.resize(enc_size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES);
		//string decrypted(new char[enc_size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES], enc_size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES
	
		unsigned long long decrypted_len = 0;
		if (!crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char*)decrypted.c_str(), &decrypted_len, NULL, enc, enc_size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES, NULL, 0, nonce_3, key)) {
			printf("success\n");
			enc_string.clear();
			std::string decompressed_data = gzip::decompress((char *)decrypted.c_str(), enc_size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES - crypto_aead_chacha20poly1305_IETF_ABYTES);
			return decompressed_data;
		}
		enc_string.clear();
		return string("");
	}

	string CipherContext::Encrypt(string&& in) {
		auto plain_string = std::move(in);
		unsigned char* plain = (unsigned char*)plain_string.c_str();
		auto plain_size = plain_string.size();
		unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
		std::string compressed_data = gzip::compress((char*)plain, plain_size);

		plain = (unsigned char*)compressed_data.c_str();
		plain_size = compressed_data.size();
		string ciphertext;
		ciphertext.resize(plain_size + crypto_aead_chacha20poly1305_IETF_ABYTES);
		unsigned long long ciphertext_len;

		randombytes_buf(nonce, sizeof nonce);
		if(!crypto_aead_chacha20poly1305_ietf_encrypt((unsigned char*)ciphertext.c_str(), &ciphertext_len, 
			plain, plain_size, NULL, 0, NULL, nonce, key)){
			plain_string.clear();
			printf("successs\n");
			string out;
			out.resize(ciphertext_len + crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
			memcpy((void*)out.c_str(), nonce, sizeof nonce);
			memcpy((void *)&(out.c_str()[sizeof nonce]), ciphertext.c_str(), ciphertext_len);
			return out;
		}
		return string("");
	}
}