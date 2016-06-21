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

HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &dwDesiredAccess, DWORD dwMandatory=0);
inline HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &&dwDesiredAccess, DWORD dwMandatory=0) { return OpenProcessWrapper(dwProcessId, dwDesiredAccess, dwMandatory); }

#endif //COMMON_H
