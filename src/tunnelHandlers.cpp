#include <windows.h>
#include "Handlers.h"
#include "Handlers_Utils.h"
#include "constants.h"
#include "listeners.h"
#include <string>
#include "pivots.h"
#include <tsmap.h>
#include "Connection.h"
//#define BUFSIZE 512
//using namespace std;
//
//namespace handlers {
//
//	/*map<int, pivotHandler> pivotHandlers = {
//		{sliverpb::MsgPivotStartListenerReq,static_cast<pivotHandler>(pivotStartListenerHandler)},
//		{sliverpb::MsgPivotPeerEnvelope,static_cast<pivotHandler>(pivotPeerEnvelopeHandler)}
//	};*/
//
//	map<int, beaconTunnelHandler> beaconTunnelHandlers = {
//		{sliverpb::MsgSocksData,static_cast<beaconPivotHandler>(beaconSocksDataHandler)},
//		{sliverpb::MsgTunnelData,static_cast<beaconPivotHandler>(beaconTunnelDataHandler)},
//		{sliverpb::MsgTunnelClose,static_cast<beaconPivotHandler>(beaconTunnelCloseHandler)},
//	};
//
//	map<int, beaconTunnelHandler>& getBeaconTunnelHandlers() {
//		return beaconTunnelHandlers;
//	}
//
//
//	sliverpb::Envelope beaconSocksDataHandler(sliverpb::Envelope env, shared_ptr<Beacon> b) {
//		sliverpb::SocksData req;
//		req.ParseFromString(env.data());
//		sliverpb::Envelope e;
//		return e;
//	}
//}