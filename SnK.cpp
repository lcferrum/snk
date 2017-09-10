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
	RevertToSelf();
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

void ImpersonateLocalSystem()
{
	if (!fnNtQuerySystemInformation) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": NtQuerySystemInformation not found!"<<std::endl;
#endif
		return;
	}

	HANDLE hCurToken;	//Token for the current process
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurToken)) {
		SYSTEM_HANDLE_INFORMATION *pshi=NULL;
		DWORD ret_size=0, cur_len=0;
		NTSTATUS st;
		
		//NtQuerySystemInformation before XP returns actual read size in ReturnLength rather than needed size
		//NtQuerySystemInformation(SystemHandleInformation) retreives unknown number of SYSTEM_HANDLE_ENTRY structures
		//So we can't tell for sure how many bytes will be needed to store information for each process because thread count and name length varies between processes
		//Each iteration buffer size is increased by 4KB
		do {
			delete[] (BYTE*)pshi;
			pshi=(SYSTEM_HANDLE_INFORMATION*)new BYTE[(cur_len+=4096)];
		} while ((st=fnNtQuerySystemInformation(SystemHandleInformation, pshi, cur_len, &ret_size))==STATUS_INFO_LENGTH_MISMATCH);
		
		if (NT_SUCCESS(st)&&ret_size&&pshi->Count) {
#if DEBUG>=3
			std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": NtQuerySystemInformation.ReturnLength="<<ret_size<<std::endl;
#endif
			//Search SYSTEM_HANDLE_INFORMATION for current process token to get right SYSTEM_HANDLE_ENTRY.ObjectType for token
			//Search is carried out from the end because new handles are appended to the end of the list and so are the handles for just launched current process
			DWORD pid=GetCurrentProcessId();
			ULONG entry_idx=pshi->Count;
			BYTE token_type;
			do {
				entry_idx--;
				if ((HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue==hCurToken&&pshi->Handle[entry_idx].OwnerPid==pid) {
					token_type=pshi->Handle[entry_idx].ObjectType;
					//Get Local System SID
					PSID ssid;
					SID_IDENTIFIER_AUTHORITY sia_nt=SECURITY_NT_AUTHORITY;
					if (AllocateAndInitializeSid(&sia_nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &ssid)) {
						//Search SYSTEM_HANDLE_INFORMATION for Local System token
						//Search is carried out from the beginning - processes launched by Local System are happen to be at start of the list
						bool token_found=false;
						for (entry_idx=0; entry_idx<pshi->Count&&!token_found; entry_idx++) if (pshi->Handle[entry_idx].ObjectType==token_type) {
							if (HANDLE hProcess=OpenProcessWrapper(pshi->Handle[entry_idx].OwnerPid, PROCESS_QUERY_INFORMATION|PROCESS_DUP_HANDLE)) {
								//ImpersonateLoggedOnUser requires hToken to have TOKEN_QUERY|TOKEN_DUPLICATE rights if it's primary token and TOKEN_QUERY|TOKEN_IMPERSONATE if it's impersonation token
								//Under NT4 imersonating logged on user with impersonation token duplicated from another process actualy have deteriorating effects on OpenProcessToken
								//So we are excluding TOKEN_IMPERSONATE from DuplicateHandle's dwDesiredAccess so ImpersonateLoggedOnUser would fail on impersonation tokens
								HANDLE hSysToken;	//Local System token
								if (DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue, GetCurrentProcess(), &hSysToken, TOKEN_QUERY|TOKEN_DUPLICATE, FALSE, 0)) {
									if(!GetTokenInformation(hSysToken, TokenUser, NULL, 0, &ret_size)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER) {
										PTOKEN_USER ptu=(PTOKEN_USER)new BYTE[ret_size];
										if (GetTokenInformation(hSysToken, TokenUser, (PVOID)ptu, ret_size, &ret_size)&&EqualSid(ptu->User.Sid, ssid)) {
#if DEBUG>=3
											std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem:"<<__LINE__<<L": ImpersonateLoggedOnUser(PID="<<pshi->Handle[entry_idx].OwnerPid<<L"): "<<((token_found=ImpersonateLoggedOnUser(hSysToken))?L"TRUE":L"FALSE")<<std::endl;
#else
											token_found=ImpersonateLoggedOnUser(hSysToken);
#endif
										}
										delete[] (BYTE*)ptu;
									}
									CloseHandle(hSysToken);
								}
								CloseHandle(hProcess);
							}
						}
						FreeSid(ssid);
					}
					break;
				}
			} while (entry_idx);
		}
		
		delete[] (BYTE*)pshi;
		CloseHandle(hCurToken);
	}
}