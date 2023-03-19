#pragma once
#include <string>
#include "sliver.pb.h"

using namespace std;

namespace handlers {
	sliverpb::Envelope wrapResponse(int64_t, google::protobuf::Message&);
}