#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

namespace processes {
	class WinProcess {
	public:
		WinProcess(PROCESSENTRY32);
		WinProcess(const WinProcess& other);
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