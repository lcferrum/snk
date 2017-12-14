#include "AccessHacks.h"
#include "Common.h"
#include "Externs.h"
#include <cstddef>		//offsetof
#include <aclapi.h>		//GetSecurityInfo
#include <accctrl.h>	//SE_KERNEL_OBJECT
#include <winternl.h>	//NT_SUCCESS, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_ENTRY

#define DEBUG 3	//REMOVE THIS
#ifdef DEBUG
#include <iostream>
#endif

#define SE_DEBUG_PRIVILEGE (20L)		//Grants r/w access to any process
#define SE_BACKUP_PRIVILEGE (17L)		//Grants read access to any file
#define SE_LOAD_DRIVER_PRIVILEGE (10L)	//Grants device driver load/unload rights [currently no use]
#define SE_RESTORE_PRIVILEGE (18L)		//Grants write access to any file
#define SE_SECURITY_PRIVILEGE (8L)		//Grants r/w access to audit and security messages [no use]
#define SE_IMPERSONATE_PRIVILEGE (29L)	//Grants user impersonation privileges

#define ACC_WOW64FSREDIRDISABLED		(1<<0)
#define ACC_LOCALSYSTEMIMPERSONATED		(1<<1)
#define	ACC_DEBUGENABLED				(1<<2)

extern pWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection;
extern pWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection;

std::unique_ptr<AccessHacks> AccessHacks::instance;

bool AccessHacks::MakeInstance() 
{
	if (instance) return false;
	
	instance.reset(new AccessHacks());
	return true;
}

AccessHacks::AccessHacks(): 
	acc_state(), err_state(), wow64_fs_redir(), hSysToken(NULL), pOrigSD(NULL), pOrigDACL(NULL), token_type(0xFFFFFFFF)
{}

AccessHacks::~AccessHacks() 
{
	PrivateWow64RevertWow64FsRedirection();
	PrivateRevertToSelf();
	
	if (hSysToken) CloseHandle(hSysToken);
	if (pOrigSD) LocalFree(pOrigSD);
}

void AccessHacks::ResetErrors()
{
	if (instance) instance->err_state=0;
}

bool AccessHacks::EnableDebugPrivileges()
{
	if (!instance) return false;
	else return instance->PrivateEnableDebugPrivileges();
}

bool AccessHacks::PrivateEnableDebugPrivileges()
{
	//Do nothing if we already failed once
	if (err_state&ACC_DEBUGENABLED) return false;
	//Actually calling all the thing second time if it was already succesfully called won't do any harm - it will also succeed
	if (acc_state&ACC_DEBUGENABLED) return true;

	HANDLE tokenHandle;
	bool success=true;
	
	DWORD needed_privs[]={SE_DEBUG_PRIVILEGE, SE_BACKUP_PRIVILEGE, SE_LOAD_DRIVER_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE, SE_IMPERSONATE_PRIVILEGE};

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
		PTOKEN_PRIVILEGES privileges=(PTOKEN_PRIVILEGES)new BYTE[offsetof(TOKEN_PRIVILEGES, Privileges)+sizeof(LUID_AND_ATTRIBUTES)*sizeof(needed_privs)/sizeof(DWORD)];

		privileges->PrivilegeCount=0;
		for (DWORD priv: needed_privs) {
			privileges->Privileges[privileges->PrivilegeCount].Attributes=SE_PRIVILEGE_ENABLED;
			privileges->Privileges[privileges->PrivilegeCount].Luid.HighPart=0;
			privileges->Privileges[privileges->PrivilegeCount].Luid.LowPart=priv;
			privileges->PrivilegeCount++;
		}

		if (!AdjustTokenPrivileges(tokenHandle, FALSE, privileges, 0, NULL, NULL))
			success=false;
		
		delete[] (BYTE*)privileges;
		CloseHandle(tokenHandle);
	}
	
	(success?acc_state:err_state)|=ACC_DEBUGENABLED;
	return success;
}

bool AccessHacks::Wow64DisableWow64FsRedirection()
{
	if (!instance) return false;
	else return instance->PrivateWow64DisableWow64FsRedirection();
}

bool AccessHacks::PrivateWow64DisableWow64FsRedirection()
{
	//Do nothing if we already failed once
	if (err_state&ACC_WOW64FSREDIRDISABLED) return false;
	//Actually calling Wow64DisableWow64FsRedirection second time (with saved OldValue or new one) if it was already succesfully called won't do any harm - it will also succeed
	if (acc_state&ACC_WOW64FSREDIRDISABLED) return true;
	
	if (fnWow64DisableWow64FsRedirection&&fnWow64DisableWow64FsRedirection(&wow64_fs_redir)) {
		acc_state|=ACC_WOW64FSREDIRDISABLED;
		return true;
	} else {
		err_state|=ACC_WOW64FSREDIRDISABLED;
		return false;
	}
}

void AccessHacks::Wow64RevertWow64FsRedirection()
{
	if (instance) instance->PrivateWow64RevertWow64FsRedirection();
}

void AccessHacks::PrivateWow64RevertWow64FsRedirection()
{
	if (fnWow64RevertWow64FsRedirection&&acc_state&ACC_WOW64FSREDIRDISABLED) {
		fnWow64RevertWow64FsRedirection(wow64_fs_redir);
		acc_state&=~ACC_WOW64FSREDIRDISABLED;
	}
}

bool AccessHacks::ImpersonateLocalSystem()
{
	if (!instance) return false;
	else return instance->PrivateImpersonateLocalSystem();
}

bool AccessHacks::PrivateImpersonateLocalSystem()
{
	//Do nothing if we already failed once
	if (err_state&ACC_LOCALSYSTEMIMPERSONATED) return false;
	if (acc_state&ACC_LOCALSYSTEMIMPERSONATED) return true;
	
	PSID ssid;
	SID_IDENTIFIER_AUTHORITY sia_nt=SECURITY_NT_AUTHORITY;
	bool success=false;
	if (AllocateAndInitializeSid(&sia_nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &ssid)) {
		HANDLE hOwnToken;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hOwnToken)) {
			if (PTOKEN_USER own_tu=GetTokenUserInformation(hOwnToken)) {
				if (EqualSid(own_tu->User.Sid, ssid)) {
#if DEBUG>=3
					std::wcerr<<L"" __FILE__ ":PrivateImpersonateLocalSystem:"<<__LINE__<<L": Already Local System"<<std::endl;
#endif
					success=true;
				} else {
					if (hSysToken) {
						if (ImpersonateLoggedOnUser(hSysToken)) {
#if DEBUG>=3
							std::wcerr<<L"" __FILE__ ":PrivateImpersonateLocalSystem:"<<__LINE__<<L": ImpersonateLoggedOnUser(CACHED TOKEN): TRUE"<<std::endl;
#endif
							success=true;
						} else {
							CloseHandle(hSysToken);
							hSysToken=NULL;
						}
					}

					if (!hSysToken) if (ImpersonateLocalSystemVista(ssid)||ImpersonateLocalSystem2k(ssid, hOwnToken)||ImpersonateLocalSystemNT4(ssid, own_tu->User.Sid)) {
						success=true;
					}
				}

				FreeTokenUserInformation(own_tu);
			}
			CloseHandle(hOwnToken);
		}
		
		FreeSid(ssid);
	}

	(success?acc_state:err_state)|=ACC_LOCALSYSTEMIMPERSONATED;
	return success;
}

void AccessHacks::RevertToSelf()
{
	if (instance) instance->PrivateRevertToSelf();
}

void AccessHacks::PrivateRevertToSelf()
{
	if (acc_state&ACC_LOCALSYSTEMIMPERSONATED) {
		::RevertToSelf();
		acc_state&=~ACC_LOCALSYSTEMIMPERSONATED;
	}
}

bool AccessHacks::ImpersonateLocalSystem2k(PSID ssid, HANDLE hOwnToken)
{
	//This function caches succesfully impersonated token so it can used later directly (PrivateImpersonateLocalSystem)
	//Caching prolog (cheking if there is already cached token) is in calling function - ImpersonateLocalSystem

	//Non-intrusive method of impersonating Local System
	//We are enumerating all the tokens opened by windows processes to find Local System one
	//Then we just duplicate it to our processes and use it to impersonate Local System
	//Caveat here is that we are depending on some other process to have already opened Local System token
	
	//N.B.:
	//Though NT4 method will work here and it's less memory consuming, this method is preferable for 2k-XP because it is non-intrusive

	bool imp_successful=false;
	SYSTEM_HANDLE_INFORMATION *pshi;
	
	//If token object type is not known yet - clean cache so own token will be included in system handle enumeration
	if (CachedNtQuerySystemHandleInformation(&pshi, token_type==0xFFFFFFFF)&&pshi->Count) {
		ULONG entry_idx;
		//If token object type is not known yet - search for it
		if (token_type==0xFFFFFFFF) {
			//Search SYSTEM_HANDLE_INFORMATION for current process token to get right SYSTEM_HANDLE_ENTRY.ObjectType for token
			//Search is carried out from the end because new handles are appended to the end of the list and so are the handles for just launched current process
			DWORD pid=GetCurrentProcessId();
			entry_idx=pshi->Count;
			do {
				entry_idx--;
				if ((HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue==hOwnToken&&pshi->Handle[entry_idx].OwnerPid==pid) {
					token_type=pshi->Handle[entry_idx].ObjectType;
					break;
				}
			} while (entry_idx);
		}
		//Search SYSTEM_HANDLE_INFORMATION for Local System token
		//Search is carried out from the beginning - processes launched by Local System are happen to be at start of the list
		for (entry_idx=0; entry_idx<pshi->Count&&!imp_successful; entry_idx++) if (pshi->Handle[entry_idx].ObjectType==token_type) {
			if (HANDLE hProcess=OpenProcessWrapper(pshi->Handle[entry_idx].OwnerPid, PROCESS_DUP_HANDLE)) {
				//ImpersonateLoggedOnUser requires hToken to have TOKEN_QUERY|TOKEN_DUPLICATE rights if it's primary token and TOKEN_QUERY|TOKEN_IMPERSONATE if it's impersonation token
				//Under NT4 impersonating logged on user with impersonation token duplicated from another process actualy have deteriorating effects on OpenProcessToken
				//So we are excluding TOKEN_IMPERSONATE from DuplicateHandle's dwDesiredAccess so ImpersonateLoggedOnUser would fail on impersonation tokens
				if (DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue, GetCurrentProcess(), &hSysToken, TOKEN_QUERY|TOKEN_DUPLICATE, FALSE, 0)) {
					if (PTOKEN_USER ptu=GetTokenUserInformation(hSysToken)) {
						if (EqualSid(ptu->User.Sid, ssid)) {
#if DEBUG>=3
							std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystem2k:"<<__LINE__<<L": ImpersonateLoggedOnUser(PID="<<pshi->Handle[entry_idx].OwnerPid<<L"): "<<((imp_successful=ImpersonateLoggedOnUser(hSysToken))?L"TRUE":L"FALSE")<<std::endl;
#else
							imp_successful=ImpersonateLoggedOnUser(hSysToken);
#endif
						}
						FreeTokenUserInformation(ptu);
					}
					//If impersonation was succesful - cache hSysToken, it will be closed on AccessHacks destruction
					if (!imp_successful) CloseHandle(hSysToken);
				}
				CloseHandle(hProcess);
			}
		}
	}
	
	//Set hSysToken to NULL on unsuccessfull impersonation because caching algorithm relies on it to be NULL if impersonation was not succesfull
	if (!imp_successful) hSysToken=NULL;
	return imp_successful;
}

bool AccessHacks::ImpersonateLocalSystemVista(PSID ssid)
{
	//This function caches succesfully impersonated token so it can used later directly (PrivateImpersonateLocalSystem)
	//Caching prolog (checking if there is already cached token) is in calling function - ImpersonateLocalSystem

	//Non-intrusive method of impersonating Local System that works on Vista+
	//We are enumerating all the processes in search of Local System one
	//When it is found, we open it with TOKEN_DUPLICATE and using it to call ImpersonateLoggedOnUser
	//This way we don't depend on any other process to open Local System token for us
	
	//N.B.: 
	//Local System processes on Vista+ happen to have their token DACL with TOKEN_DUPLICATE rights set for the users that have enough rights to open them for TOKEN_QUERY
	//This doesn't happen on previous OS versions - here we have to set needed DACL permissions manually for this method to work (see ImpersonateLocalSystemNT4)

	bool imp_successful=false;
	SYSTEM_PROCESS_INFORMATION *pspi_all;
	
	if (CachedNtQuerySystemProcessInformation(&pspi_all)) {
		//First step is to find a process with Local System token
		//We try to open it with TOKEN_QUERY|TOKEN_DUPLICATE right away
		SYSTEM_PROCESS_INFORMATION *pspi_cur=pspi_all;
		while (pspi_cur&&!imp_successful) {
			if (HANDLE hProcess=OpenProcessWrapper((ULONG_PTR)pspi_cur->UniqueProcessId, PROCESS_QUERY_INFORMATION)) {
				HANDLE hToken=NULL;
				if (OpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_DUPLICATE, &hToken)) {
					if (PTOKEN_USER sys_tu=GetTokenUserInformation(hToken)) {
						if (EqualSid(sys_tu->User.Sid, ssid)) {
							//Now just call ImpersonateLoggedOnUser for this token
							if (DuplicateTokenEx(hToken, TOKEN_QUERY|TOKEN_DUPLICATE, NULL, SecurityImpersonation, TokenPrimary, &hSysToken)) {
#if DEBUG>=3
								std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystemVista:"<<__LINE__<<L": ImpersonateLoggedOnUser(PID="<<(ULONG_PTR)pspi_cur->UniqueProcessId<<L"): "<<((imp_successful=ImpersonateLoggedOnUser(hSysToken))?L"TRUE":L"FALSE")<<std::endl;
#else
								imp_successful=ImpersonateLoggedOnUser(hSysToken);
#endif
								//If impersonation was succesful - cache hSysToken, it will be closed on AccessHacks destruction
								if (!imp_successful) CloseHandle(hSysToken);
							}
						}
						FreeTokenUserInformation(sys_tu);
					}
					CloseHandle(hToken);
				}
				CloseHandle(hProcess);
			}
			pspi_cur=pspi_cur->NextEntryOffset?(SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pspi_cur+pspi_cur->NextEntryOffset):NULL;
		}
	}
	
	//Set hSysToken to NULL on unsuccessfull impersonation because caching algorithm relies on it to be NULL if impersonation was not succesfull
	if (!imp_successful) hSysToken=NULL;
	return imp_successful;
}

bool AccessHacks::ImpersonateLocalSystemNT4(PSID ssid, PSID usid)
{
	//This function caches succesfully impersonated token so it can used later directly (PrivateImpersonateLocalSystem)
	//Caching prolog (cheking if there is already cached token) is in calling function - ImpersonateLocalSystem

	//Intrusive method of impersonating Local System
	//We are enumerating all the processes in search of Local System one
	//When it is found, we modify it's token DACL to allow TOKEN_DUPLICATE for current user needed for ImpersonateLoggedOnUser to work
	//This way we don't depend on any other process to open Local System token for us
	
	//N.B.: 
	//This method works on NT4+, given that user have enough rights
	//Though it most likely find it's way only on NT4 because we have other working non-intrusive methods for newer OSes 

	bool imp_successful=false;
	SYSTEM_PROCESS_INFORMATION *pspi_all;
	
	if (CachedNtQuerySystemProcessInformation(&pspi_all)) {
		//First step is to find a process with Local System token
		//We open it with TOKEN_QUERY (to get TokenUser information incl. SID) and READ_CONTROL|WRITE_DAC (to be able to tap into DACL) permissions
		//We won't be able to get TOKEN_DUPLICATE rights with Local System token needed for ImpersonateLoggedOnUser right now
		SYSTEM_PROCESS_INFORMATION *pspi_cur=pspi_all;
		while (pspi_cur&&!imp_successful) {
			if (HANDLE hProcess=OpenProcessWrapper((ULONG_PTR)pspi_cur->UniqueProcessId, PROCESS_QUERY_INFORMATION)) {
				HANDLE hToken=NULL;
				if (OpenProcessToken(hProcess, TOKEN_QUERY|READ_CONTROL|WRITE_DAC, &hToken)) {
					if (PTOKEN_USER sys_tu=GetTokenUserInformation(hToken)) {
						if (EqualSid(sys_tu->User.Sid, ssid)) {
							//Local System token found now it's time to tap into it's DACL
							//After it we will reopen token with added TOKEN_DUPLICATE permission and cache it for further use (also it will allow ImpersonateLocalSystem2k to work for SnK instance launched in parallel)
							//All what is left is calling ImpersonateLoggedOnUser and reverting token DACL to it's former state
							if (GrantDaclPermissions(hToken, usid, TOKEN_DUPLICATE)) {
								CloseHandle(hToken);
								if (OpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_DUPLICATE|READ_CONTROL|WRITE_DAC, &hToken)) {
									if (DuplicateTokenEx(hToken, TOKEN_QUERY|TOKEN_DUPLICATE, NULL, SecurityImpersonation, TokenPrimary, &hSysToken)) {
#if DEBUG>=3
										std::wcerr<<L"" __FILE__ ":ImpersonateLocalSystemNT4:"<<__LINE__<<L": ImpersonateLoggedOnUser(PID="<<(ULONG_PTR)pspi_cur->UniqueProcessId<<L"): "<<((imp_successful=ImpersonateLoggedOnUser(hSysToken))?L"TRUE":L"FALSE")<<std::endl;
#else
										imp_successful=ImpersonateLoggedOnUser(hSysToken);
#endif
										//If impersonation was succesful - cache hSysToken, it will be closed on AccessHacks destruction
										if (!imp_successful) CloseHandle(hSysToken);
									}
									//On successful tap we revert this PID's DACL to original state
									RevertDaclPermissions(hToken);
								} else
									hToken=NULL;
							}
						}
						FreeTokenUserInformation(sys_tu);
					}
					if (hToken) CloseHandle(hToken);
				}
				CloseHandle(hProcess);
			}
			pspi_cur=pspi_cur->NextEntryOffset?(SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pspi_cur+pspi_cur->NextEntryOffset):NULL;
		}
	}
	
	//Set hSysToken to NULL on unsuccessfull impersonation because caching algorithm relies on it to be NULL if impersonation was not succesfull
	if (!imp_successful) hSysToken=NULL;
	return imp_successful;
}

bool AccessHacks::GrantDaclPermissions(HANDLE hToken, PSID pSid, DWORD dwAccessPermissions)
{
	//This function saves original security descriptor (incl. DACL) for token so it can be reverted later (RevertDaclPermissions)
	//If there is already previously saved security descriptor - it is closed and replaced with new one
	
	bool tap_successful=false;
	if (pOrigSD) LocalFree(pOrigSD);
	
	if (GetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOrigDACL, NULL, &pOrigSD)==ERROR_SUCCESS) {
		EXPLICIT_ACCESS ea_for_sid;
		PACL pNewDACL;
		ea_for_sid.grfAccessPermissions=dwAccessPermissions;
		ea_for_sid.grfAccessMode=GRANT_ACCESS;	//This ACCESS_MODE combines the specified rights with any existing allowed or denied rights of the trustee
		ea_for_sid.grfInheritance=NO_INHERITANCE;
		ea_for_sid.Trustee.pMultipleTrustee=NULL;
		ea_for_sid.Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
		ea_for_sid.Trustee.TrusteeForm=TRUSTEE_IS_SID;
		ea_for_sid.Trustee.TrusteeType=TRUSTEE_IS_USER;
		ea_for_sid.Trustee.ptstrName=(LPWSTR)pSid;
		
		if (SetEntriesInAcl(1, &ea_for_sid, pOrigDACL, &pNewDACL)==ERROR_SUCCESS) {
			if (SetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL)==ERROR_SUCCESS)
				tap_successful=true;
			LocalFree(pNewDACL);
		}

		if (!tap_successful) LocalFree(pOrigSD);
	}
	
	if (!tap_successful) pOrigSD=NULL;
	return tap_successful;
}

void AccessHacks::RevertDaclPermissions(HANDLE hToken)
{
	if (pOrigSD) {
		SetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pOrigDACL, NULL);
		LocalFree(pOrigSD);
		pOrigSD=NULL;
	}
}

bool AccessHacks::PrivateIsGranted(const DWORD *privs, DWORD cnt)
{
	HANDLE tokenHandle;
	bool granted=false;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
		PPRIVILEGE_SET privileges=(PPRIVILEGE_SET)new BYTE[offsetof(PRIVILEGE_SET, Privilege)+sizeof(LUID_AND_ATTRIBUTES)*cnt];
		
		for (privileges->PrivilegeCount=0; privileges->PrivilegeCount<cnt; privileges->PrivilegeCount++) {
			privileges->Privilege[privileges->PrivilegeCount].Attributes=SE_PRIVILEGE_ENABLED;
			privileges->Privilege[privileges->PrivilegeCount].Luid.HighPart=0;
			privileges->Privilege[privileges->PrivilegeCount].Luid.LowPart=privs[privileges->PrivilegeCount];
		}
		privileges->Control=PRIVILEGE_SET_ALL_NECESSARY;
		
		BOOL res;
		PrivilegeCheck(tokenHandle, privileges, &res);
		granted=res;
		
		delete[] (BYTE*)privileges;
		CloseHandle(tokenHandle);
	}
}

bool AccessHacks::IsGrantedIMPERSONATE()
{
	DWORD privs[]={SE_IMPERSONATE_PRIVILEGE};
	if (!instance) return false;
	else return instance->PrivateIsGranted(privs, 1);
}

bool AccessHacks::IsLocalSytemImpersonated()
{
	if (!instance) return false;
	else return instance->acc_state&ACC_LOCALSYSTEMIMPERSONATED;
}
