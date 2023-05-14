#pragma once
#include <string>
#include <vector>
#include <TlHelp32.h>

namespace processes {
	class WinProcess {
	public:
		WinProcess(PROCESSENTRY32);
		int pid;
		int ppid;
		std::string exe;
		std::string owner;
		std::string arch;
		std::string cmdLine;
		int sessionID;
	};
	
	std::vector<WinProcess> ps();
}