#include "pivots.h"
#include <sodium.h>
#include <thread>
#include <future>
#include "constants.h"
using namespace std;

namespace pivots {
	static uint64_t MyPeerID = 0;
	static bool generated = false;
	uint64_t generatePeerID() {
		if (generated == true) {
			return MyPeerID;
		}
		unsigned char buf[8];
		randombytes_buf(buf, 8);
		uint64_t id = *((uint64_t*)&buf[0]);
		MyPeerID = id;
		generated = true;
		return id;
	}

	uint64_t getPeerID() {
		return MyPeerID;
	}
	PivotListener::PivotListener(uint32_t _id, sliverpb::PivotType _type,unique_ptr<Listener>& _ln, const string& _bindAddress, shared_ptr<Beacon> _beacon) : id(_id), bindAddress(_bindAddress), type(_type) {
		this->beacon = _beacon;
		this->ln = std::move(_ln);
		this->stop = false;
	}
	void PivotListener::StartListening(shared_ptr<Beacon> b) {
		std::thread t1{
			[&] {
				while (1) {
					if (stop) {
						return;
					}
					auto conn = this->ln->Accept();
					if (conn != nullptr){
						conn->peerKeyExchange();
						conn->beacon = this->beacon;
						//this->connections.insert(std::pair(conn->downstreamPeerID, conn));
						this->connections[conn->downstreamPeerID] = conn;
						conn->Start();
					}
				}
			}
		};
		this->listener_thread = std::move(t1);
	}
	unique_ptr<vector<sliverpb::NetConnPivot>> PivotListener::GetNetConnPivots() {
		auto pivots = make_unique<vector<sliverpb::NetConnPivot>>();
		for (auto it = this->connections.begin();it != this->connections.end();++it) {
			sliverpb::NetConnPivot p;
			p.set_peerid(it->second->downstreamPeerID);
			p.set_remoteaddress(this->bindAddress);
			pivots->push_back(p);
		}
		return pivots;
	}
	void PivotListener::StopListening() {
		stop = true;
		this->ln->Stop();
		listener_thread.join();
		this->ln->Clean();
		for (auto it = this->connections.begin();it != this->connections.end();++it) {
			it->second->Stop();
		}
	}
	void PivotListener::StartListening() {
		std::thread t1{
			[&] {
				while (1) {
					auto conn = this->ln->Accept();
					if (conn->peerKeyExchange()) {
						//conn->upstream = this->upstream;
						this->connections.insert(std::pair(conn->downstreamPeerID, conn));
						conn->Start();
					}
				}
			}
		};
		t1.detach();
	}
	void PivotListener::Accept() {
		auto conn = this->ln->Accept();
		conn->peerKeyExchange();
		//conn->upstream = this->upstream;
		this->connections.insert(std::pair(conn->downstreamPeerID, conn));
	}
	void StartConnection(shared_ptr<PivotConn> conn) {
		std::thread t1{
			[conn] {
				while (1) {
					auto env = conn->ReadEnvelope();
					if (env.type() == sliverpb::MsgPivotPeerEnvelope) {
						sliverpb::PivotPeerEnvelope peer_env;
						peer_env.ParseFromString(env.data());
						auto peers = peer_env.peers();
						sliverpb::PivotPeer p;
						p.set_name("DAMP_BOW");
						p.set_peerid(pivots::getPeerID());
						peers.Add(std::move(p));
						peer_env.add_peers();
						string serialized;
						peer_env.SerializeToString(&serialized);
						env.set_data(serialized);
						//conn->upstream->push(std::move(env));
					}
				}
			}
		};
		t1.detach();
		std::thread t2{
			[conn] {
				while (1) {
					sliverpb::Envelope env;
					/*if (conn->downstream->try_pop(env)) {
						conn->WriteEnvelope(env);
					}*/
				}
			}
		};
		t2.detach();
	}
	void StartListener(shared_ptr<PivotListener> listener) {
		std::thread t1{
			[listener] {
				while (1) {
					auto conn = listener->ln->Accept();
					conn->peerKeyExchange();
					//conn->upstream = listener->upstream;
					listener->connections.insert(std::pair(conn->downstreamPeerID, conn));
					StartConnection(conn);
				}
			}
		};
		t1.detach();
	}
	uint64_t findNextPeerID(const sliverpb::PivotPeerEnvelope& env) {
		auto peers = env.peers();
		for (auto it = peers.begin(); it != peers.end();++it) {
			auto a = it->peerid();
#ifdef DEBUG
			cout << "my peer id: " << MyPeerID << endl << "it->peerid: " << it->peerid() << endl;
#endif
			if (it->peerid() == MyPeerID && it != peers.begin()) {
				return (it - 1)->peerid();
			}
		}
		return 0;
	}
}