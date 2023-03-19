#pragma once
#include <string>
#include <atomic>
using namespace std;

namespace token {

    typedef struct _userInfo {
        string uid;
        string gid;
        string username;
        
    }UserInfo,PUserInfo;

    string SidToString(PSID sid);
    string GetUserNameString();
    UserInfo GetCurrentUserInfo();
    HANDLE getToken();
    bool makeToken(const string&, const string&, const string&, uint32_t);
    bool revertToken();
}