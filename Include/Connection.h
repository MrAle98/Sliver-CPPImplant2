#pragma once
#include<iostream>
#include "Client.h"
#include <chrono>
#include "concurrent_queue.h"

using namespace std;
namespace transports {
	class Connection {
	public:
		Connection(const string&, unique_ptr<IClient>&, const string & = "", int interval = 5, int jitter = 1, int reconnectInterval = 30);
		bool ConnectionInit();
		void ConnectionStart();
		bool ConnectionSend(sliverpb::Envelope&);
		unique_ptr<sliverpb::Envelope> ConnectionRecv();
		//void ConnectionClose();
		//void ConnectionCleanup();
		std::chrono::seconds GetReconnectInterval();
		int GetConnectionErrors();
		std::chrono::duration<int> reconnectInterval;
		int connectionErrors = 0;
		string activeC2;
		string proxyURL;
		std::mutex m;
		std::unique_ptr<IClient> client;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> to_send_queue;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> recv_queue;
	};
}