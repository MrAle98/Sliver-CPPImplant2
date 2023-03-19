#pragma once
#include "MemoryModule.h"
#include <string>
#include <vector>
using namespace std;

namespace extensions {
	class WindowsExtension
	{
	public:
		WindowsExtension(const string&, const string&, const string&, const string&);
		string Call(const string&,const string&);
		void goCallback(const char*, int);
	private:
		string os;
		string init;
		string name;
		HMEMORYMODULE module = NULL;
	};

	BOOL addExtension(const string&, const string&, const string&, const string&);
	string runExtension(const string&, const string&, const string&);
	vector<string> listExtensions();
}

