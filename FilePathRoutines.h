#ifndef FPROUTINES_H
#define FPROUTINES_H

#include <string>
#include <vector>
#include <windows.h>

namespace FPRoutines {
	void FillDriveList();
	void FillServiceMap();
	std::wstring GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read);
	std::vector<std::wstring> GetModuleList(HANDLE hProcess, bool full);
	std::wstring GetHandlePath(HANDLE hFile, bool full);
	bool GetCommandLine(HANDLE hProcess, std::wstring &cmdline);
}

#endif //FPROUTINES_H