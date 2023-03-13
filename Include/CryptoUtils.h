#pragma once
#include <sodium.h>
#include <string>
#include <memory>
#include <botan/otp.h>
#include <botan/base32.h>

using namespace std;

namespace crypto {

	typedef struct _ECCkeyPair {
		unsigned char pb_key[32];
		unsigned char pv_key[32];
	}ECCKeyPair, * PECCKeyPair;

	string RandomKey();
	string GetServerECCPublicKey();
	shared_ptr<ECCKeyPair> getKeyPair();
	string ECCEncryptToServer(const string&);
	uint32_t GetTOTP(const chrono::system_clock::time_point&);
}