#pragma once
#include <string>
#include <atomic>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <lm.h>

#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 256
#define FULL_NAME_LENGTH 271
#define TOKEN_TYPE_LENGTH 30
#define TOKEN_IMPERSONATION_LENGTH 50
#define TOKEN_INTEGRITY_LENGTH 10
#define COMMAND_LENGTH 1000
#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16
#define SystemHandleInformationSize             1024 * 1024 * 10

using namespace std;

namespace token {

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
        USHORT ProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    }  SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef enum _POOL_TYPE {
        NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed,
        DontUseThisType,
        NonPagedPoolCacheAligned,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS
    } POOL_TYPE, * PPOOL_TYPE;

    typedef struct _OBJECT_TYPE_INFORMATION {
        UNICODE_STRING Name;
        ULONG TotalNumberOfObjects;
        ULONG TotalNumberOfHandles;
        ULONG TotalPagedPoolUsage;
        ULONG TotalNonPagedPoolUsage;
        ULONG TotalNamePoolUsage;
        ULONG TotalHandleTableUsage;
        ULONG HighWaterNumberOfObjects;
        ULONG HighWaterNumberOfHandles;
        ULONG HighWaterPagedPoolUsage;
        ULONG HighWaterNonPagedPoolUsage;
        ULONG HighWaterNamePoolUsage;
        ULONG HighWaterHandleTableUsage;
        ULONG Inis_token_validAttributes;
        GENERIC_MAPPING GenericMapping;
        ULONG is_token_validAccess;
        BOOLEAN SecurityRequired;
        BOOLEAN MaintainHandleCount;
        USHORT MaintainTypeList;
        POOL_TYPE PoolType;
        ULONG PagedPoolUsage;
        ULONG NonPagedPoolUsage;
    } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

    typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
    typedef UNICODE_STRING* POBJECT_NAME_INFORMATION;

    using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    typedef struct {
        HANDLE TokenHandle;
        int TokenId;
        DWORD SessionId;
        wchar_t Username[FULL_NAME_LENGTH];
        wchar_t TokenType[TOKEN_TYPE_LENGTH];
        wchar_t TokenImpersonationLevel[TOKEN_IMPERSONATION_LENGTH];
        wchar_t TokenIntegrity[TOKEN_INTEGRITY_LENGTH];
    } TOKEN;

    typedef struct _userInfo {
        string uid;
        string gid;
        string username;
        
    }UserInfo,PUserInfo;

    class Token {
    public:
        Token(HANDLE);
        Token(const Token&);
        std::wstring toString();

        HANDLE TokenHandle;
        LUID TokenId;
        LUID LogonSessionId;
        ULONG LogonType;
        std::wstring Username;
        TOKEN_TYPE TokenType;
        SECURITY_IMPERSONATION_LEVEL TokenImpLevel;
        DWORD TokenIntegrity;    
        DWORD PrivilegesCount;
    };
    
    string SidToString(PSID sid);
    string GetUserNameString();
    UserInfo GetCurrentUserInfo();
    HANDLE getToken();
    bool makeToken(const string&, const string&, const string&, uint32_t);
    bool revertToken();
    bool Impersonate(const std::string& username);
    bool Impersonate(const int pid);
}