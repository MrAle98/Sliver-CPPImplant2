#include "Encoders.h"

namespace encoders {
    Base64::Base64(const string& chars) : base64_chars(chars){

    }
	string Base64::Decode(string&& in) {
        auto enc = std::move(in);
		return this->from_base64(std::move(enc));
	}
	string  Base64::Encode(string&& in) {
        auto dec = in;
		return this->to_base64(std::move(dec));
	}

	string Base64::to_base64(string&&in) {
        auto data = std::move(in);
        int counter = 0;
        uint32_t bit_stream = 0;
        std::string encoded;
        int offset = 0;
        for (unsigned char c : data) {
            auto num_val = static_cast<unsigned int>(c);
            offset = 16 - counter % 3 * 8;
            bit_stream += num_val << offset;
            if (offset == 16) {
                encoded += base64_chars.at(bit_stream >> 18 & 0x3f);
            }
            if (offset == 8) {
                encoded += base64_chars.at(bit_stream >> 12 & 0x3f);
            }
            if (offset == 0 && counter != 3) {
                encoded += base64_chars.at(bit_stream >> 6 & 0x3f);
                encoded += base64_chars.at(bit_stream & 0x3f);
                bit_stream = 0;
            }
            counter++;
        }
        data.clear();
        if (offset == 16) {
            encoded += base64_chars.at(bit_stream >> 12 & 0x3f);
            encoded += "==";
        }
        if (offset == 8) {
            encoded += base64_chars.at(bit_stream >> 6 & 0x3f);
            encoded += '=';
        }
        char ch = '=';
        encoded.erase(remove(encoded.begin(), encoded.end(), ch), encoded.end());
        return encoded;
	}

    string Base64::from_base64(string&& in) {
        auto data = std::move(in);
        int counter = 0;
        uint32_t bit_stream = 0;
        std::string decoded;
        int offset = 0;
        for (unsigned char c : data) {
            auto num_val = base64_chars.find(c);
            if (num_val != std::string::npos) {
                offset = 18 - counter % 4 * 6;
                bit_stream += num_val << offset;
                if (offset == 12) {
                    decoded += static_cast<char>(bit_stream >> 16 & 0xff);
                }
                if (offset == 6) {
                    decoded += static_cast<char>(bit_stream >> 8 & 0xff);
                }
                if (offset == 0 && counter != 4) {
                    decoded += static_cast<char>(bit_stream & 0xff);
                    bit_stream = 0;
                }
            }
            else if (c != '=') {
                data.clear();
                return std::string();
            }
            counter++;
        }
        data.clear();
        return decoded;
    }
}