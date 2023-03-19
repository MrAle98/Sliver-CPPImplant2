#pragma once
#include <windows.h>
#include <string>
#include "PivotConn.h"
#include "concurrent_vector.h"


namespace pivots {
	class Listener {
	public:
		virtual shared_ptr<PivotConn> Accept() = 0;
		virtual bool Stop() = 0;
		virtual void Clean() = 0;
	};

	class NamedPipeListener : public Listener {
	public:
		NamedPipeListener(std::string pipe_name);
		std::shared_ptr<PivotConn> Accept() override;
		bool Stop() override;
		void Clean() override;
	private:
		std::string pipe_name;
		HANDLE temp_pipeRead;
		HANDLE temp_pipeWrite;
	};

	class TCPListener : public Listener {
	public:
		TCPListener(const std::string&);
		std::shared_ptr<PivotConn> Accept() override;
		bool Stop() override;
		void Clean() override;
	private:
		string bind_address;
		SOCKET listen_socket;
		
	};
}