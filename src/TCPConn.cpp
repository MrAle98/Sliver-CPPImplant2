#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "PivotConn.h"
#include "CryptoUtils.h"
#include "sliver.pb.h"
#include "constants.h"
#include "pivots.h"
extern string instanceID;

namespace pivots {
	TCPConn::TCPConn(SOCKET _client_socket) : client_socket(_client_socket) {
	}
	bool TCPConn::Check() {
		return true;
	}
	TCPConn::~TCPConn() {
		if (t.joinable())
			t.join();
	}
	void TCPConn::Stop() {
		this->stop = true;
		if (t.joinable())
			t.join();
	}
	void TCPConn::Start() {
		std::thread t1{
			[&] {
				while (1) {
					if (stop) {
						closesocket(this->client_socket);
						return;
					}
					try {
						auto env = ReadEnvelope();
						if (env.type() == sliverpb::MsgPivotPeerEnvelope || env.type() == sliverpb::MsgPivotPeerEnvelopeNoResponse) {
							sliverpb::PivotPeerEnvelope peer_env;
							peer_env.ParseFromString(env.data());
							auto peers = peer_env.peers();
							for (auto it = peers.begin();it != peers.end();++it) {
								auto a = it->peerid();
							}
							auto p = peer_env.add_peers();
							auto temp = instanceID;
							temp.resize(8);
							p->set_name(temp);
							p->set_peerid(pivots::getPeerID());
							for (auto it = peers.begin();it != peers.end();++it) {
								auto a = it->peerid();
							}
							string serialized;
							peer_env.SerializeToString(&serialized);
							env.set_data(serialized);
							sliverpb::Envelope resp;
							if (env.type() == sliverpb::MsgPivotPeerEnvelope) {
								if (beacon->BeaconRecv(env, resp)) {
									WriteEnvelope(resp);
								}
								else {
									throw exception("BeaconRecv returned false");
								}
							}
							else if (env.type() == sliverpb::MsgPivotPeerEnvelopeNoResponse) {
								if (!beacon->BeaconSend(env))
									throw exception("BeaconSend returned false");
							}
						}
					}
					catch(exception &e){
#ifdef DEBUG
						cout << std::format("TCP Conn catched exception: {}", e.what()) << endl;
#endif
						stop = true;
					}
				}
			} 
		};
		this->t = std::move(t1);
	}
	sliverpb::Envelope TCPConn::ReadEnvelope() {
		auto data = read();
		auto plain = ctx.Decrypt(std::move(data));
		sliverpb::Envelope env;
		env.ParseFromString(plain);
		return env;
	}

	bool TCPConn::WriteEnvelope(const sliverpb::Envelope& env) {
		string serialized;
		env.SerializeToString(&serialized);
		auto enc = this->ctx.Encrypt(std::move(serialized));
		return this->write(enc);
	}

	string TCPConn::read() {
		int res = 0;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->client_socket, &fds);
		auto ret = select(0, &fds, NULL, &fds, NULL);
		if (ret) {
			SIZE_T len = 0;
			res = recv(this->client_socket, (char*)&len, sizeof(SIZE_T), 0);
			if (res == 0 || res == SOCKET_ERROR) {
				throw exception{ std::format("recv failed with error {}",GetLastError()).c_str() };
			}
			std::string out;
			out.resize(len);
			res = recv(this->client_socket, (char*)out.c_str(), len, 0);
			if (res == 0 || res == SOCKET_ERROR) {
				throw exception{ std::format("recv failed with error {}",GetLastError()).c_str() };
			}
			return out;
		}
		throw exception{ std::format("select failed with error {}",GetLastError()).c_str() };
	}

	bool TCPConn::write(const string& in) {
		DWORD written = 0;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->client_socket, &fds);
		auto ret = select(0, NULL, &fds, &fds, NULL);
		if (ret) {
			SIZE_T len = in.size();
			written = send(this->client_socket, (char*)&len, sizeof len, 0);
			if (written != sizeof len)
				throw exception{ std::format("send failed with error {}",GetLastError()).c_str() };
			written = send(this->client_socket, (char*)in.c_str(), len, 0);
			if (written != len)
				throw exception{ std::format("send failed with error {}",GetLastError()).c_str() };
			return true;
		}
		throw exception{ std::format("select failed with error {}",GetLastError()).c_str() };
	}
	bool TCPConn::peerKeyExchange() {
		try {
			auto s = this->read();
			sliverpb::PivotHello hello;
			hello.ParseFromString(s);
			this->downstreamPeerID = hello.peerid();
			auto key = crypto::RandomKey();
			this->ctx.SetKey(key);
			sliverpb::PivotHello resp;
			resp.set_sessionkey(key);
			string serialized_resp;
			resp.SerializeToString(&serialized_resp);
			this->write(serialized_resp);
			return true;
		}
		catch (exception& e) {
			return false;
		}
	}
}