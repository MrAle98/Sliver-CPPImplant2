#include "listeners.h"
#include <string>
#include "PivotConn.h"
#include <sddl.h>
#include <accctrl.h>
#include <AclAPI.h>
#define BUFSIZE 40000 

using namespace std;
typedef struct
{
    PSID Sid;
    PSID SidLow;
    PACL SAcl;

    PSECURITY_DESCRIPTOR SecDec;
} SMB_PIPE_SEC_ATTR, * PSMB_PIPE_SEC_ATTR;
namespace pivots {
    VOID SmbSecurityAttrOpen(PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecurityAttr)
    {
        SID_IDENTIFIER_AUTHORITY SidIdAuth = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY SidLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
        EXPLICIT_ACCESSW         ExplicitAccess = { 0 };
        DWORD                    Result = 0;
        PACL                     DAcl = NULL;
        /* zero them out. */
        memset(SmbSecAttr, 0, sizeof(SMB_PIPE_SEC_ATTR));
        memset(SecurityAttr, 0, sizeof(PSECURITY_ATTRIBUTES));

        if (!AllocateAndInitializeSid(&SidIdAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &SmbSecAttr->Sid))
        {
            printf("AllocateAndInitializeSid failed: %u\n", GetLastError());
            return;
        }
        printf("SmbSecAttr->Sid: %p\n", SmbSecAttr->Sid);

        ExplicitAccess.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
        ExplicitAccess.grfAccessMode = SET_ACCESS;
        ExplicitAccess.grfInheritance = NO_INHERITANCE;
        ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ExplicitAccess.Trustee.ptstrName = (LPWCH)SmbSecAttr->Sid;

        Result = SetEntriesInAclW(1, &ExplicitAccess, NULL, &DAcl);
        if (Result != ERROR_SUCCESS)
        {
            printf("SetEntriesInAclW failed: %u\n", Result);
        }
        printf("DACL: %p\n", DAcl);

        if (!AllocateAndInitializeSid(&SidLabel, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &SmbSecAttr->SidLow))
        {
            printf("AllocateAndInitializeSid failed: %u\n", GetLastError());
        }
        printf("sidLow: %p\n", SmbSecAttr->SidLow);

        SmbSecAttr->SAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,MAX_PATH);
        if (!InitializeAcl(SmbSecAttr->SAcl, MAX_PATH, ACL_REVISION_DS))
        {
            printf("InitializeAcl failed: %u\n", GetLastError());
        }

        if (!AddMandatoryAce(SmbSecAttr->SAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->SidLow))
        {
            printf("AddMandatoryAce failed: %u\n", GetLastError());
        }

        // now build the descriptor
        SmbSecAttr->SecDec = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!InitializeSecurityDescriptor(SmbSecAttr->SecDec, SECURITY_DESCRIPTOR_REVISION))
        {
            printf("InitializeSecurityDescriptor failed: %u\n", GetLastError());
        }

        if (!SetSecurityDescriptorDacl(SmbSecAttr->SecDec, TRUE, DAcl, FALSE))
        {
            printf("SetSecurityDescriptorDacl failed: %u\n", GetLastError());
        }

        if (!SetSecurityDescriptorSacl(SmbSecAttr->SecDec, TRUE, SmbSecAttr->SAcl, FALSE))
        {
            printf("SetSecurityDescriptorSacl failed: %u\n", GetLastError());
        }

        SecurityAttr->lpSecurityDescriptor = SmbSecAttr->SecDec;
        SecurityAttr->bInheritHandle = FALSE;
        SecurityAttr->nLength = sizeof(SECURITY_ATTRIBUTES);
    }

    VOID SmbSecurityAttrFree(PSMB_PIPE_SEC_ATTR SmbSecAttr)
    {
        if (SmbSecAttr->Sid)
        {
            FreeSid(SmbSecAttr->Sid);
            SmbSecAttr->Sid = NULL;
        }

        if (SmbSecAttr->SidLow)
        {
            FreeSid(SmbSecAttr->SidLow);
            SmbSecAttr->SidLow = NULL;
        }

        if (SmbSecAttr->SAcl)
        {
            HeapFree(GetProcessHeap(),0,SmbSecAttr->SAcl);
            SmbSecAttr->SAcl = NULL;
        }

        if (SmbSecAttr->SecDec)
        {
            HeapFree(GetProcessHeap(), 0,SmbSecAttr->SecDec);
            SmbSecAttr->SecDec = NULL;
        }
    }
	NamedPipeListener::NamedPipeListener(string _pipe_name) : pipe_name(_pipe_name){}
	shared_ptr<PivotConn> NamedPipeListener::Accept() {

		SMB_PIPE_SEC_ATTR   SmbSecAttr = { 0 };
		SECURITY_ATTRIBUTES SecurityAttr = { 0 };
        SECURITY_ATTRIBUTES SecurityAttr2 = { 0 };
		/* Setup attributes to allow "anyone" to connect to our pipe */
		SmbSecurityAttrOpen(&SmbSecAttr, &SecurityAttr);

		string tmp = this->pipe_name;
		/*string stdstring{ "D:(A;;0x1f019f;;;WD)" };
		PSECURITY_DESCRIPTOR psd;
		ULONG sizesd = 0;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(stdstring.c_str(), SDDL_REVISION_1, &psd, &sizesd)) {
#ifdef DEBUG
			int error = GetLastError();
			std::cout << std::format("ConvertStringSecurityDescriptorToSecurityDescriptorA failed with error {}",error) << std::endl;
#endif 
		}
		SECURITY_ATTRIBUTES sa = { 0 };
		sa.lpSecurityDescriptor = psd;
		sa.nLength = sizeof sa;*/
		/*sa.bInheritHandle = FALSE;*/
        SMB_PIPE_SEC_ATTR smbsecattr = { 0 };
        SECURITY_ATTRIBUTES sa = { 0 };
        SmbSecurityAttrOpen(&smbsecattr, &sa);
		this->temp_pipeRead = CreateNamedPipeA(
			tmp.append(string{"_readserver"}).c_str(),     // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_BYTE |       // message type pipe 
			PIPE_READMODE_BYTE |   // message-read mode 
			PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			&sa);
		tmp = this->pipe_name;
		this->temp_pipeWrite = CreateNamedPipeA(
			tmp.append(string{ "_writeserver" }).c_str(),     // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_BYTE |       // message type pipe 
			PIPE_READMODE_BYTE |   // message-read mode 
			PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			&sa);
        SmbSecurityAttrFree(&smbsecattr);
		if (ConnectNamedPipe(this->temp_pipeRead, NULL) && ConnectNamedPipe(this->temp_pipeWrite,NULL)) {
			shared_ptr<PivotConn> conn = make_shared<NamedPipeConn>(this->temp_pipeRead, this->temp_pipeWrite);
			this->temp_pipeRead = INVALID_HANDLE_VALUE;
			this->temp_pipeWrite = INVALID_HANDLE_VALUE;
			return conn;
		}
		return nullptr;
	}
	bool NamedPipeListener::Stop() {
		auto res = CancelIoEx(this->temp_pipeRead, NULL);
		res = CancelIoEx(this->temp_pipeWrite, NULL);
		return true;
	}
	void NamedPipeListener::Clean() {
		DisconnectNamedPipe(this->temp_pipeRead);
		DisconnectNamedPipe(this->temp_pipeWrite);
		CloseHandle(this->temp_pipeRead);
		CloseHandle(this->temp_pipeWrite);
		this->temp_pipeRead = INVALID_HANDLE_VALUE;
		this->temp_pipeWrite = INVALID_HANDLE_VALUE;
	}
}