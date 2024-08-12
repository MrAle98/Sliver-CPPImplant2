#pragma once
//#define NOMINMAX 1 
#include<windows.h>
#include <string>
using namespace std;

namespace encoders {
	class Encoder {
	public:
		virtual string Encode(string&&) = 0;
		virtual string Decode(string&&) = 0;
	};
	enum EncoderType {
		Base64EncoderID = 13,
		HexEncoderID = 92
	};
	Encoder* GetEncoder(EncoderType type);
	tuple<int,Encoder*> GetRandomEncoder();
	class Base64 : public Encoder{
	public:
		Base64(const string& chars = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ");
		string Encode(string&&) override;
		string Decode(string&&) override;
	private:
		string to_base64(string&&);
		string from_base64(string&&);
		string base64_chars;
	};
}