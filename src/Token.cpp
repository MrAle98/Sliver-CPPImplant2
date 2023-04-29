#include <windows.h>
#include <sddl.h>
#include <security.h>
#include <secext.h>
#include "Token.h"
#include <atomic>

using namespace std;

namespace token {
    HANDLE current_token = INVALID_HANDLE_VALUE;

    HANDLE getToken() {
        return current_token;
    }

    bool Impersonate(const std::string& username) {
        return true;
    }

    bool Impersonate(const int pid) {
        HANDLE hToken = INVALID_HANDLE_VALUE;
        HANDLE hProc = INVALID_HANDLE_VALUE;
        hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
        if (hProc == INVALID_HANDLE_VALUE)
            return false;
        OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken);
        if (hToken == INVALID_HANDLE_VALUE)
            return false;
        current_token = hToken;
        return true;
    }

    bool makeToken(const string& domain, const string& username, const string& password, uint32_t logonType) {
        if (logonType == 0) {
            logonType = LOGON32_LOGON_NEW_CREDENTIALS;
        }
        HANDLE token;
        auto res = LogonUserA(username.c_str(), domain.c_str(), password.c_str(), logonType,LOGON32_PROVIDER_DEFAULT, &token);
        if (res) {
            current_token = token;
        }
        return res;
    }
    bool revertToken() {
        current_token = INVALID_HANDLE_VALUE;
        return true;
    }
    string SidToString(PSID sid) {
        LPSTR sid_string;
        auto b = ConvertSidToStringSidA(sid, &sid_string);
        string str{ sid_string };
        auto a = LocalFree(sid_string);
        return str;
    }

    string GetUserNameString() {
        string a;
        ULONG size = 0;
        GetUserNameExA(NameSamCompatible,NULL, &size);
        a.resize(size);
        GetUserNameExA(NameSamCompatible, (LPSTR)a.c_str(), &size);
        return a;
    }
    UserInfo GetCurrentUserInfo() {
        HANDLE p = GetCurrentProcess();
        HANDLE t;
        OpenProcessToken(p, TOKEN_QUERY, &t);
        DWORD size = 0;
        auto res = GetTokenInformation(t, TokenUser, NULL, 0, &size);
        std::string tu;
        tu.resize(size);
        res = GetTokenInformation(t, TokenUser, (LPVOID)tu.c_str(), size, &size);
        res = GetTokenInformation(t, TokenPrimaryGroup, NULL, 0, &size);
        std::string tpg;
        tpg.resize(size);
        res = GetTokenInformation(t, TokenPrimaryGroup,(LPVOID)tpg.c_str(), size, &size);
        auto uid = SidToString(((PTOKEN_USER)(tu.c_str()))->User.Sid);
        auto gid = SidToString(((PTOKEN_PRIMARY_GROUP)(tpg.c_str()))->PrimaryGroup);
        auto username = GetUserNameString();
        return UserInfo{ uid = uid,gid = gid,username = username };
    }
}