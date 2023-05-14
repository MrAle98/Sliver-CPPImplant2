#include <Windows.h>
#include "processes.h"
#include "Token.h"
#include <format>
#include <exception>
#include <locale>
#include <codecvt>

namespace processes {

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
		auto res = tk.Username;
		CloseHandle(hToken);
		CloseHandle(hProc);
		return res;
	}
	LUID getProcSessionID(int pid) {
		HANDLE hProc = INVALID_HANDLE_VALUE;
		HANDLE hToken = INVALID_HANDLE_VALUE;
		LUID sessID;
		sessID.HighPart = 0;
		sessID.LowPart = -1;
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProc == INVALID_HANDLE_VALUE || hProc == 0)
			return sessID;
		if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
			CloseHandle(hProc);
			return sessID;
		}
		token::Token tk{ hToken };
		auto res = tk.LogonSessionId;
		CloseHandle(hToken);
		CloseHandle(hProc);
		return res;
	}

	WinProcess::WinProcess(PROCESSENTRY32 entry) : pid(entry.th32ProcessID),ppid(entry.th32ParentProcessID),exe(entry.szExeFile){

	}
	std::vector<WinProcess> ps() {
		HANDLE snapshot = INVALID_HANDLE_VALUE;
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE || snapshot == 0)
			throw std::exception(std::format("[-] CreateToolhelp32Snapshot failed with error: {}", GetLastError()).c_str());
		
		PROCESSENTRY32 entry = { 0 };
		if (!Process32First(snapshot, &entry)) {
			CloseHandle(snapshot);
			throw std::exception(std::format("[-] Process32First failed with error: {}", GetLastError()).c_str());
		}
		std::vector<WinProcess> results;
		while (1) {
			results.push_back(WinProcess{ entry });
		}
	}
}