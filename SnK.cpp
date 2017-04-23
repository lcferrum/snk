#include <cstdio>
#include <cwchar>
#include <stack>
#include <iostream>
#include <limits>
#include <cstddef>		//offsetof
#include "ProcessUsage.h"
#include "Controller.h"
#include "Killers.h"
#include "Extras.h"
#include "Common.h"
#include "Hout.h"

extern pWcoutMessageBox fnWcoutMessageBox;
extern pWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection;
extern pWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection;
extern template class Controller<Processes, Killers>;

void EnableDebugPrivileges();

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