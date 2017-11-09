#ifndef FPROUTINES_H
#define FPROUTINES_H

#include <string>
#include <vector>
#include <windows.h>

namespace FPRoutines {
	void FillDriveList();
	void FillServiceMap();
	std::wstring GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read);
	std::vector<std::pair<std::wstring, std::wstring>> GetModuleList(HANDLE hProcess);
	std::wstring GetHandlePath(HANDLE hFile, bool full);
}

#endif //FPROUTINES_H