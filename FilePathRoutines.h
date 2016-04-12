#ifndef FPROUTINES_H
#define FPROUTINES_H

#include <string>
#include <vector>
#include <windows.h>

namespace FPRoutines {
	void FillDriveMap();
	void FillServiceMap();
	std::wstring GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read);
	std::vector<std::pair<std::wstring, std::wstring>> GetModuleList(HANDLE hProcess);
}

#endif //FPROUTINES_H