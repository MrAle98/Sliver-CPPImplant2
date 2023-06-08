#include "Utils.h"
#include <Windows.h>
namespace utils {
	bool is_number(const std::string& s){
        std::string s1 = "";
        if (s.length() >= 2 && s[0] == '0' && s[1] == 'x') {
            s1.assign(&s[2]);
        }
        else {
            s1 = s;
        }
		return !s1.empty() && std::find_if(s1.begin(),
			s1.end(), [](unsigned char c) { return !std::isxdigit(c); }) == s1.end();
	}

    std::string ws2s(const std::wstring& s)
    {
        int len;
        int slength = (int)s.length() + 1;
        len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0);
        std::string r(len, '\0');
        WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, &r[0], len, 0, 0);
        return r;
    }
}