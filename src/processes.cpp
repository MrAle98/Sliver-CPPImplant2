#include <Windows.h>
#include "processes.h"
#include "Token.h"
#include <format>
#include <exception>
#include <locale>
#include <codecvt>
#include "Utils.h"
#include <mutex>

namespace processes {

	std::string getProcArch(int pid) {
		HANDLE hProc = INVALID_HANDLE_VALUE;
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProc == INVALID_HANDLE_VALUE || hProc == 0)
			return "";
		BOOL isWow64 = FALSE;
		if (!IsWow64Process(hProc, &isWow64)) {
			CloseHandle(hProc);
			return "";
		}
		if (isWow64)
			return "x86";
		else
			return "x86_x64";
	}
	std::string getProcOwner(int pid) {
		HANDLE hProc = INVALID_HANDLE_VALUE;
		HANDLE hToken = INVALID_HANDLE_VALUE;
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProc == INVALID_HANDLE_VALUE || hProc == 0)
			return "";
		if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
			CloseHandle(hProc);
			return "";
		}
		token::Token tk{ hToken };
		CloseHandle(hToken);
		CloseHandle(hProc);
		return utils::ws2s(tk.Username);
	}
	
	/*std::string getCmdLine(int pid) {
		HANDLE snapshot = INVALID_HANDLE_VALUE;
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
		if (snapshot == INVALID_HANDLE_VALUE || snapshot == 0)
			return "";

	}*/
	std::int32_t getProcSessionID(int32_t pid) {
		uint32_t sessionID = -1;
		if (!ProcessIdToSessionId(pid, (DWORD*)&sessionID))
			return -1;
		else
			return sessionID;
	}

	WinProcess::WinProcess(PROCESSENTRY32 entry) : pid(entry.th32ProcessID),ppid(entry.th32ParentProcessID),exe(entry.szExeFile){
		this->arch = getProcArch(pid);
		this->owner = getProcOwner(pid);
		this->cmdLine = "";
		this->sessionID = getProcSessionID(pid);
	}

	WinProcess::WinProcess(const WinProcess& other) : pid(other.pid), ppid(other.ppid), exe(other.exe), owner(other.owner), arch(other.arch), cmdLine(other.cmdLine), sessionID(other.sessionID){
		return;
	}
	std::vector<WinProcess> ps() {
		HANDLE snapshot = INVALID_HANDLE_VALUE;
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE || snapshot == 0)
			throw std::exception(std::format("[-] CreateToolhelp32Snapshot failed with error: {}", GetLastError()).c_str());
		
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof PROCESSENTRY32;
		if (!Process32First(snapshot, &entry)) {
			CloseHandle(snapshot);
			throw std::exception(std::format("[-] Process32First failed with error: {}", GetLastError()).c_str());
		}
		std::vector<WinProcess> results;
		while (1) {
			results.push_back(WinProcess{ entry });
			entry.dwSize = sizeof PROCESSENTRY32;
			if (!Process32Next(snapshot, &entry))
				break;
		}
		CloseHandle(snapshot);
		return results;
	}
}