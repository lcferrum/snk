#ifndef HELP_H
#define HELP_H

#include <windows.h>

void PrintUsage();
void PrintVersion();

bool MultiWildcardCmp(const wchar_t* wild, const wchar_t* string);

bool CheckIfFileExists(const wchar_t* fpath);

HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &dwDesiredAccess, DWORD dwMandatory=0);
inline HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &&dwDesiredAccess, DWORD dwMandatory=0) { return OpenProcessWrapper(dwProcessId, dwDesiredAccess, dwMandatory); }


#endif //HELP_H
