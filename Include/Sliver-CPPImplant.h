// Sliver-CPPImplant2.h : Include file for standard system include files,
// or project specific include files.

#pragma once

typedef int (*goCallback)(const char*, int);
#ifdef EXE
extern "C" {
	int main();

}
#endif
#ifdef SHARED
extern "C" {
	__declspec(dllexport) int __cdecl Entry();
	__declspec(dllexport) VOID APIENTRY DonutApiVoid(VOID);
	__declspec(dllexport) int __cdecl entrypoint(char* argsBuffer, uint32_t bufferSize, goCallback callback);

}
#endif


// TODO: Reference additional headers your program requires here.
