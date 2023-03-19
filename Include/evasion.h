#pragma once
#include <windows.h>

namespace evasion {
	BOOL patchAMSI();
	BOOL patchETW(BOOL);
	bool spoof(int, STARTUPINFOEXA&);
}