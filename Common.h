#ifndef COMMON_H
#define COMMON_H

#include <vector>
#include <stack>
#include <string>
#include <windows.h>

void PrintUsage();
void PrintVersion();

bool MultiWildcardCmp(const wchar_t* wild, const wchar_t* string, const wchar_t* delim=L";", bool is_path=true);

//Warning: will corrupt ARGV beyond repair
//skip_argc - how many ARGVs will be skipped (first ARGV is typically program path)
void MakeRulesFromArgv(int argc, wchar_t** argv, std::stack<std::wstring> &rules, int skip_argc=1);

//Returns compare result (PID found in list or not) or list processing result (without errors or not)
//If pid_list=NULL - won't process list and will use supplied uptr_array
//If uptr_array=NULL - will use own internal uptr_array
//If pid=NULL - won't compare PID and will just process list
bool PidListCmp(const wchar_t* pid_list, std::vector<ULONG_PTR> *uptr_array, const ULONG_PTR *pid);
inline bool PidListCmp(const wchar_t* pid_list, std::vector<ULONG_PTR> &uptr_array) { return PidListCmp(pid_list, &uptr_array, NULL); }
inline bool PidListCmp(std::vector<ULONG_PTR> &uptr_array, const ULONG_PTR &pid) { return PidListCmp(NULL, &uptr_array, &pid); }
inline bool PidListCmp(std::vector<ULONG_PTR> &uptr_array, const ULONG_PTR &&pid) { return PidListCmp(NULL, &uptr_array, &pid); }

bool CheckIfFileExists(const wchar_t* fpath);

std::wstring GetNamePartFromFullPath(const std::wstring& fpath);

LPVOID GetTokenInformationWrapper(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass);
inline PTOKEN_USER GetTokenUserInformation(HANDLE hToken) { return (PTOKEN_USER)GetTokenInformationWrapper(hToken, TokenUser); }
inline void FreeTokenUserInformation(PTOKEN_USER ptu) { delete[] (BYTE*)ptu; }
inline PTOKEN_GROUPS GetTokenGroupsInformation(HANDLE hToken) { return (PTOKEN_GROUPS)GetTokenInformationWrapper(hToken, TokenGroups); }
inline void FreeTokenGroupsInformation(PTOKEN_GROUPS ptg) { delete[] (BYTE*)ptg; }

//OpenProcessWrapper will try to remove PROCESS_VM_READ access flag and change PROCESS_QUERY_INFORMATION to PROCESS_QUERY_LIMITED_INFORMATION if it can't open process with supplied dwDesiredAccess
//dwMandatory contains access flags that OpenProcessWrapper shoudn't remove (or change) from dwDesiredAccess to try to open process with more relaxed access requirements
HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &dwDesiredAccess, DWORD dwMandatory=0);
inline HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &&dwDesiredAccess, DWORD dwMandatory=0) { return OpenProcessWrapper(dwProcessId, dwDesiredAccess, dwMandatory); }

//Typical buffer sizes for various NtQuerySystemInformation and NtQueryInformationProcess calls
//Store and get them here so not to guess them every time these functions are called
namespace TypicalBufferSize {
	DWORD SystemHandleInformation(DWORD size=0);
	DWORD SystemProcessInformation(DWORD size=0);
	DWORD ProcessBasicInformation(DWORD size=0);
	DWORD SystemProcessIdInformation(DWORD size=0);
}

#endif //COMMON_H
