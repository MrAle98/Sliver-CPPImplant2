#pragma once
#include "tsmap.h"
#include "PivotConn.h"
#include "listeners.h"
#include <concurrent_queue.h>
#include "concurrent_unordered_map.h"
#include <atomic>
#include "Beacon.h"

using namespace std;
using namespace transports;
namespace pivots {
	class PivotListener {
	public:
		PivotListener(uint32_t, sliverpb::PivotType,unique_ptr<Listener>&,const string&, shared_ptr<Beacon> b);
		void StartListening();
		void StartListening(shared_ptr<Beacon>);
		void Accept();
		void StopListening();
		unique_ptr<vector<sliverpb::NetConnPivot>> GetNetConnPivots();
		uint32_t id;
		unique_ptr<Listener> ln;
		concurrency::concurrent_unordered_map<uint64_t, shared_ptr<PivotConn>> connections;
		string bindAddress;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> upstream;
		atomic<bool> stop;
		thread listener_thread;
		shared_ptr<Beacon> beacon;
		sliverpb::PivotType type;
	private:
	};
	uint64_t getPeerID();
	uint64_t generatePeerID();
	uint64_t findNextPeerID(const sliverpb::PivotPeerEnvelope&);
	void StartListener(shared_ptr<PivotListener> listener);
}