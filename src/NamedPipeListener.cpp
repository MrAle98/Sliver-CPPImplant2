#include "listeners.h"
#include <string>
#include "PivotConn.h"
#define BUFSIZE 40000 

using namespace std;

namespace pivots {

	NamedPipeListener::NamedPipeListener(string _pipe_name) : pipe_name(_pipe_name){}
	shared_ptr<PivotConn> NamedPipeListener::Accept() {
		string tmp = this->pipe_name;
		this->temp_pipeRead = CreateNamedPipeA(
			tmp.append(string{"_readserver"}).c_str(),     // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_BYTE |       // message type pipe 
			PIPE_READMODE_BYTE |   // message-read mode 
			PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);
		tmp = this->pipe_name;
		this->temp_pipeWrite = CreateNamedPipeA(
			tmp.append(string{ "_writeserver" }).c_str(),     // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_BYTE |       // message type pipe 
			PIPE_READMODE_BYTE |   // message-read mode 
			PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);
		if (ConnectNamedPipe(this->temp_pipeRead, NULL) && ConnectNamedPipe(this->temp_pipeWrite,NULL)) {
			shared_ptr<PivotConn> conn = make_shared<NamedPipeConn>(this->temp_pipeRead, this->temp_pipeWrite);
			this->temp_pipeRead = INVALID_HANDLE_VALUE;
			this->temp_pipeWrite = INVALID_HANDLE_VALUE;
			return conn;
		}
		return nullptr;
	}
	bool NamedPipeListener::Stop() {
		auto res = CancelIoEx(this->temp_pipeRead, NULL);
		res = CancelIoEx(this->temp_pipeWrite, NULL);
		return true;
	}
	void NamedPipeListener::Clean() {
		DisconnectNamedPipe(this->temp_pipeRead);
		DisconnectNamedPipe(this->temp_pipeWrite);
		CloseHandle(this->temp_pipeRead);
		CloseHandle(this->temp_pipeWrite);
		this->temp_pipeRead = INVALID_HANDLE_VALUE;
		this->temp_pipeWrite = INVALID_HANDLE_VALUE;
	}
}