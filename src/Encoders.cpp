#include "encoders.h"
#include <vector>

#define N_TYPES 1

using namespace std;

namespace encoders {
	const int encodermodulus = 101;
	const int maxN = 999999;
	EncoderType types[N_TYPES] = { EncoderType::Base64EncoderID };
	Encoder* GetEncoder(EncoderType ID) {
		switch (ID) {
		case EncoderType::Base64EncoderID:
			return new Base64();
		case EncoderType::HexEncoderID:
			break;
		}
	}
	tuple<int,Encoder*> GetRandomEncoder() {
		int n = rand() % N_TYPES;
		Encoder* encoder = GetEncoder(types[n]);
		int nonce = rand() * encodermodulus + types[n];
		return make_tuple(nonce, encoder);
	}
}