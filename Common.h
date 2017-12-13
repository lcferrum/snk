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

bool CheckIfFileExists(const wchar_t* fpath);

std::wstring GetNamePartFromFullPath(const std::wstring& fpath);

LPVOID GetTokenInformationWrapper(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass);
inline PTOKEN_USER GetTokenUserInformation(HANDLE hToken) { return (PTOKEN_USER)GetTokenInformationWrapper(hToken, TokenUser); }
inline void FreeTokenUserInformation(PTOKEN_USER ptu) { delete[] (BYTE*)ptu; }
inline PTOKEN_GROUPS GetTokenGroupsInformation(HANDLE hToken) { return (PTOKEN_GROUPS)GetTokenInformationWrapper(hToken, TokenGroups); }
inline void FreeTokenGroupsInformation(PTOKEN_GROUPS ptg) { delete[] (BYTE*)ptg; }

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

class UniqueHandle {
private:
	bool valid;
	HANDLE handle;
public:
	HANDLE GetHandle() const { return handle; }
	bool IsValid() const { return valid; }
	HANDLE ReleaseHandle() { valid=false; return handle; }
	void ResetHandle(HANDLE new_handle) { if (valid) CloseHandle(handle); valid=true; handle=new_handle; }

	UniqueHandle(): valid(false), handle() {}
	UniqueHandle(HANDLE new_handle): valid(true), handle(new_handle) {}
	~UniqueHandle() { if (valid) CloseHandle(handle); }
	UniqueHandle(UniqueHandle &&prev_inst): valid(prev_inst.valid), handle(prev_inst.handle) { prev_inst.valid=false; }
	UniqueHandle& operator=(UniqueHandle &&prev_inst) { valid=prev_inst.valid; handle=prev_inst.handle; prev_inst.valid=false; return *this; }

	UniqueHandle(const UniqueHandle&)=delete;				
	UniqueHandle& operator=(const UniqueHandle&)=delete;
};

#endif //COMMON_H
