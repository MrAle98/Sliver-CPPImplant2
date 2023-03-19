#include "Handlers_Utils.h"

using namespace std;

namespace handlers {
	sliverpb::Envelope wrapResponse(int64_t id, google::protobuf::Message& msg){
		string data;
		msg.SerializeToString(&data);
		sliverpb::Envelope envelope;
		envelope.set_id(id);
		envelope.set_data(data);
		return envelope;
	}
}