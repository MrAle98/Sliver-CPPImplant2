#pragma once
#include <string>
using namespace std;

namespace os {
	string GetOSVersion();
	string GetHostName();
	string GetExecutableName();
	string GetUserDefaultLocaleNameString();
}