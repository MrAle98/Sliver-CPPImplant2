#include "constants.h"

namespace sliverpb {
	MsgType MsgNumber(google::protobuf::Message& msg) {
		if (msg.GetDescriptor()->name().compare("PwdReq")) {
			return MsgPwdReq;
		}
	}
}