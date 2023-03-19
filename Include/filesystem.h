#pragma once
#include <filesystem>
#include "sliver.pb.h"
using namespace std;

namespace FS {
	bool remove(const string&, error_code&,bool);
	bool mkdir(const string&, error_code&);
	string pwd(void);
	string cd(const string&);
	sliverpb::Ls ls(const string&,bool);
	bool write(const string& path,const string& data);
	string read(const string& path);
}