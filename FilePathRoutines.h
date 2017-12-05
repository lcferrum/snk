#ifndef FPROUTINES_H
#define FPROUTINES_H

#include <string>
#include <vector>
#include <memory>
#include <windows.h>

namespace FPRoutines {
	void FillDriveList();
	void FillServiceMap();
	std::wstring GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read);
	std::vector<std::wstring> GetModuleList(HANDLE hProcess, bool full);
	std::wstring GetHandlePath(HANDLE hFile, bool full);
	bool GetCmdCwdEnv(HANDLE hProcess, std::wstring &cmdline, std::wstring &cwdpath, std::unique_ptr<BYTE> &envblock);
}

#endif //FPROUTINES_H