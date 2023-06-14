#pragma once
#include <string>

using namespace std;

namespace taskrunner {
	string ExecuteAssembly(const string&, const string&, bool, bool);
	string execute(const string&, bool = true, int ppid = 0, bool usetoken = false);
	int executeShellcode(const string&);
}