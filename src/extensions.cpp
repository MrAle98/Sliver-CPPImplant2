#include "extensions.h"
#include <string>
#include<map>
#include <mutex>
#include <vector>
using namespace std;

namespace extensions {

	map<string, shared_ptr<WindowsExtension>> extensions;
	mutex mut;
	string buffer;
	mutex mut_buffer;
	typedef int(*goCallback) (const char* buff, int size);
	typedef void(*go) (char* args, uint32_t args_size, goCallback);

	int goCallback_impl(const char* buff, int size) {
		buffer.clear();
		buffer.append(buff, size);
		return 0;
	}

	WindowsExtension::WindowsExtension(const string& _data, const string& _name, const string& _os, const string& _init) : name(_name), os(_os), init(_init) {
		this->module = MemoryLoadLibrary(_data.c_str(), _data.size());
	}
	string WindowsExtension::Call(const string& func_name, const string& arguments) {
		go proc = (go)MemoryGetProcAddress(this->module, func_name.c_str());
		unique_lock lk{ mut_buffer };
		proc((char*)arguments.c_str(), arguments.size(), goCallback_impl);
		string ret = buffer;
		return ret;
	}
	BOOL addExtension(const string& _data, const string& _name, const string& _os, const string& _init) {
		unique_lock lk{ mut };
		if (extensions.contains(_name)) {
			return FALSE;
		}
		else {
			extensions.emplace(_name, make_shared<WindowsExtension>(WindowsExtension{ _data,_name,_os,_init }));
		}
		return true;
	}
	string runExtension(const string& name, const string& export_name, const string& args) {
		unique_lock lk{ mut };
		auto ext = extensions.find(name)->second;
		auto res = ext->Call(export_name, args);
		return res;
	}
	std::vector<std::string> listExtensions() {
		unique_lock lk{ mut };
		vector<string> ret;
		for (auto it = extensions.begin();it != extensions.end();++it) {
			ret.push_back(it->first);
		}
		return ret;
	}
}