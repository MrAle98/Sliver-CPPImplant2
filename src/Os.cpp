#include <windows.h>
#include "Os.h"

namespace os {
	string GetOSVersion() {
		return string{ "windows" };
	}

	string GetHostName() {
		char buf[100] = { 0 };
		DWORD size;
		GetComputerNameExA(ComputerNamePhysicalDnsHostname, buf, &size);
		string str{ buf };
		return str;
	}

	string GetExecutableName() {
		char buf[100] = { 0 };
		DWORD size;
		GetModuleFileNameA(0, buf, 100);
			string str {
			buf
		};
		return str;
	}

	string GetUserDefaultLocaleNameString() {
		wchar_t buf[LOCALE_NAME_MAX_LENGTH] = { 0 };
		GetUserDefaultLocaleName(buf, LOCALE_NAME_MAX_LENGTH);
		string str{(char*)buf, LOCALE_NAME_MAX_LENGTH };
		return str;
	}
}