#include <cstdio>
#include <cwchar>
#include <stack>
#include <iostream>
#include <limits>
#include <cstddef>		//offsetof
#include <winternl.h>	//NT_SUCCESS, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_ENTRY
#include <ntstatus.h>	//STATUS_INFO_LENGTH_MISMATCH
#include "ProcessUsage.h"
#include "Controller.h"
#include "Killers.h"
#include "Extras.h"
#include "Common.h"
#include "Hout.h"

extern pWcoutMessageBox fnWcoutMessageBox;
extern pWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection;
extern pWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection;
extern pNtQuerySystemInformation fnNtQuerySystemInformation;
extern template class Controller<Processes, Killers>;

void EnableDebugPrivileges();
void ImpersonateLocalSystem();

#ifdef OBSOLETE_WMAIN
typedef struct {
	int newmode;
} _startupinfo;
#undef _CRT_glob
extern int _CRT_glob;
extern "C" void __wgetmainargs(int*, wchar_t***, wchar_t***, int, _startupinfo*);

int main()
{
	wchar_t **enpv, **argv;
	int argc;
	_startupinfo si;
	__wgetmainargs(&argc, &argv, &enpv, _CRT_glob, &si);
#else
extern "C" int wmain(int argc, wchar_t* argv[])
{
#endif
#ifdef HIDDEN
	Extras::MakeInstance(true, L"Search and Kill");
#else
	Extras::MakeInstance(false, NULL);
#endif

	if (argc<2) {
		PrintVersion();
#ifdef HIDDEN
		if (fnWcoutMessageBox) {
			std::wcout<<L"When finished, press OK..."<<std::endl;
			fnWcoutMessageBox();
		}
#endif
		return 0;
	}
	
	CoInitialize(NULL);			//COM is needed for GetLongPathName implementation from newapis.h
	EnableDebugPrivileges();	//Will set debug privileges (administrator privileges should be already present for this to actually work)
	ImpersonateLocalSystem();
	PVOID wow64_fs_redir;		//OldValue for Wow64DisableWow64FsRedirection/Wow64RevertWow64FsRedirection
	if (fnWow64DisableWow64FsRedirection) fnWow64DisableWow64FsRedirection(&wow64_fs_redir);	//So GetLongPathName and GetFileAttributes uses correct path
	//A note on disabling Wow64FsRedirection
	//Microsoft discourages to do this process-wide and suggests disabling it right before the needed function call and reverting after
	//Main concerns here being LoadLibrary calls and delayed-loaded imports that may occur after Wow64FsRedirection being disabled and failing because of that
	//Delayed-loaded imports for Windows targets is not supported by current compiler selection (MinGW and Clang) - so it's not concern here
	//So we just have to do all the LoadLibrary calls before disabling Wow64FsRedirection (which is already done through Extras class) and we are good to go
	
	std::stack<std::wstring> rules;
	MakeRulesFromArgv(argc, argv, rules);
	Controller<Processes, Killers> controller;
	controller.MakeItDead(rules);
	
	if (fnWow64RevertWow64FsRedirection) fnWow64RevertWow64FsRedirection(wow64_fs_redir);
	CoUninitialize();

	return 0;
}

#define SE_DEBUG_PRIVILEGE (20L)		//Grants r/w access to any process
#define SE_BACKUP_PRIVILEGE (17L)		//Grants read access to any file
#define SE_LOAD_DRIVER_PRIVILEGE (10L)	//Grants device driver load/unload rights [currently no use]
#define SE_RESTORE_PRIVILEGE (18L)		//Grants write access to any file
#define SE_SECURITY_PRIVILEGE (8L)		//Grants r/w access to audit and security messages [no use]
	
void EnableDebugPrivileges()
{
	HANDLE tokenHandle;
	
	//Privileges similar to Process Explorer
	DWORD needed_privs[]={SE_DEBUG_PRIVILEGE, SE_BACKUP_PRIVILEGE, SE_LOAD_DRIVER_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE};

	if (NT_SUCCESS(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle))) {
		PTOKEN_PRIVILEGES privileges=(PTOKEN_PRIVILEGES)new BYTE[offsetof(TOKEN_PRIVILEGES, Privileges)+sizeof(LUID_AND_ATTRIBUTES)*sizeof(needed_privs)/sizeof(DWORD)];

		privileges->PrivilegeCount=0;
		for (DWORD priv: needed_privs) {
			privileges->Privileges[privileges->PrivilegeCount].Attributes=SE_PRIVILEGE_ENABLED;
			privileges->Privileges[privileges->PrivilegeCount].Luid.HighPart=0;
			privileges->Privileges[privileges->PrivilegeCount].Luid.LowPart=priv;
			privileges->PrivilegeCount++;
		}

		AdjustTokenPrivileges(tokenHandle, FALSE, privileges, 0, NULL, NULL);
		
		delete[] (BYTE*)privileges;
		CloseHandle(tokenHandle);
	}
}

/*
  typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG OwnerPid;
    BYTE ObjectType;
    BYTE HandleFlags;
    USHORT HandleValue;
    PVOID ObjectPointer;
    ULONG AccessMask;
  } SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

  typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG Count;
    SYSTEM_HANDLE_ENTRY Handle[1];
  } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
*/

void ImpersonateLocalSystem()
{
	if (!fnNtQuerySystemInformation) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": NtQuerySystemInformation not found!"<<std::endl;
#endif
		return;
	}

	//NtQuerySystemInformation before XP returns actual read size in ReturnLength rather than needed size
	//NtQuerySystemInformation(SystemHandleInformation) retreives unknown number of SYSTEM_HANDLE_ENTRY structures
	//So we can't tell for sure how many bytes will be needed to store information for each process because thread count and name length varies between processes
	//Each iteration buffer size is increased by 4KB
	SYSTEM_HANDLE_INFORMATION *pshi=NULL;
	DWORD ret_size=0, cur_len=0;
	NTSTATUS st;
	
	do {
		delete[] (BYTE*)pshi;
		pshi=(SYSTEM_HANDLE_INFORMATION*)new BYTE[(cur_len+=4096)];
	} while ((st=fnNtQuerySystemInformation(SystemHandleInformation, pshi, cur_len, &ret_size))==STATUS_INFO_LENGTH_MISMATCH);
	
	if (!NT_SUCCESS(st)||!ret_size) {
		delete[] (BYTE*)pshi;
		return;
	}
	
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": NtQuerySystemInformation.ReturnLength="<<ret_size<<std::endl;
	std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": SYSTEM_HANDLE_INFORMATION.Count="<<pshi->Count<<std::endl;
#endif

	HANDLE hCurToken;	//Token for the current process
	if (pshi->Count&&OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurToken)) {
		DWORD pid=GetCurrentProcessId();
		
		//Search SYSTEM_HANDLE_INFORMATION for current process token to get right SYSTEM_HANDLE_ENTRY.ObjectType for token
		//Search is carried out from the end because new handles are appended to the end of the list and so are the handles for just launched current process
		ULONG entry_idx=pshi->Count;
		BYTE token_type=0;

		do {
			entry_idx--;
			if (reinterpret_cast<HANDLE>(pshi->Handle[entry_idx].HandleValue)==hCurToken&&pshi->Handle[entry_idx].OwnerPid==pid) {
				token_type=pshi->Handle[entry_idx].ObjectType;
				break;
			}
		} while (entry_idx);
		
		if (token_type) {
		}
		
		CloseHandle(hCurToken);
	}
	
	delete[] (BYTE*)pshi;
}