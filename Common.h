#ifndef COMMON_H
#define COMMON_H

#include <stack>
#include <string>
#include <windows.h>
#include <winternl.h>

void PrintUsage();
void PrintVersion();

enum MWCMode:char {MWC_PTH, MWC_STR, MWC_SUB};
bool MultiWildcardCmp(const wchar_t* wild, const wchar_t* string, MWCMode mode=MWC_STR, const wchar_t* delim=L";");

//Warning: will corrupt ARGV beyond repair
//skip_argc - how many ARGVs will be skipped (first ARGV is typically program path)
void MakeRulesFromArgv(int argc, wchar_t** argv, std::stack<std::wstring> &rules, int skip_argc=1);

std::wstring GetNamePartFromFullPath(const std::wstring& fpath);

LPVOID GetTokenInformationWrapper(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass);
inline PTOKEN_USER GetTokenUserInformation(HANDLE hToken) { return (PTOKEN_USER)GetTokenInformationWrapper(hToken, TokenUser); }
inline void FreeTokenUserInformation(PTOKEN_USER ptu) { delete[] (BYTE*)ptu; }
inline PTOKEN_GROUPS GetTokenGroupsInformation(HANDLE hToken) { return (PTOKEN_GROUPS)GetTokenInformationWrapper(hToken, TokenGroups); }
inline void FreeTokenGroupsInformation(PTOKEN_GROUPS ptg) { delete[] (BYTE*)ptg; }
inline PTOKEN_PRIVILEGES GetTokenPrivilegesInformation(HANDLE hToken) { return (PTOKEN_PRIVILEGES)GetTokenInformationWrapper(hToken, TokenPrivileges); }
inline void FreeTokenPrivilegesInformation(PTOKEN_PRIVILEGES ptp) { delete[] (BYTE*)ptp; }

bool IsTokenRestrictedEx(HANDLE hToken);
bool IsTokenElevated(HANDLE hToken);

//OpenProcessWrapper will try to remove PROCESS_VM_READ access flag and change PROCESS_QUERY_INFORMATION to PROCESS_QUERY_LIMITED_INFORMATION if it can't open process with supplied dwDesiredAccess
//dwMandatory contains access flags that OpenProcessWrapper shoudn't remove (or change) from dwDesiredAccess to try to open process with more relaxed access requirements
HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &dwDesiredAccess, DWORD dwMandatory=0);
inline HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &&dwDesiredAccess, DWORD dwMandatory=0) { return OpenProcessWrapper(dwProcessId, dwDesiredAccess, dwMandatory); }

void Win32WcostreamActivate();
void Win32WcostreamDeactivate();
void Win32WcostreamEnabled(bool state);
#ifdef HIDDEN
bool Win32WcostreamMessageBox(bool ok_cancel);
#endif

bool CachedNtQuerySystemProcessInformation(SYSTEM_PROCESS_INFORMATION** spi_buffer, bool clear_cache=false);
bool CachedNtQuerySystemHandleInformation(SYSTEM_HANDLE_INFORMATION** shi_buffer, bool clear_cache=false);

#endif //COMMON_H
