#ifndef ACCESSHACKS_H
#define ACCESSHACKS_H

#include <memory>
#include <windows.h>

class AccessHacks {
private:
	static std::unique_ptr<AccessHacks> instance;
	
	DWORD acc_state;				//ACC_WOW64FSREDIRDISABLED, ACC_LOCALSYSTEMIMPPRI, ACC_LOCALSYSTEMIMPSEC, ACC_DEBUGENABLED
	PVOID wow64_fs_redir;			//OldValue for Wow64DisableWow64FsRedirection/Wow64RevertWow64FsRedirection
	HANDLE hSysToken;				//Cached Local System token for ImpersonateLocalSystem
	PSECURITY_DESCRIPTOR pOrigSD;	//Saved original token security descriptor used in RevertDaclPermissions
	PACL pOrigDACL;					//Saved original token DACL (actually points to someplace in pOrigSD) used in RevertDaclPermissions
	
	bool ImpersonateLocalSystemPrimary();
	bool ImpersonateLocalSystemSecondary();
	bool GrantDaclPermissions(HANDLE hToken, PSID pSid, DWORD dwAccessPermissions);
	void RevertDaclPermissions(HANDLE hToken);
	
	AccessHacks();
	
	bool PrivateEnableDebugPrivileges();
	bool PrivateWow64DisableWow64FsRedirection();
	void PrivateWow64RevertWow64FsRedirection();
	bool PrivateImpersonateLocalSystem();
	void PrivateRevertToSelf();
public:
	~AccessHacks();
	AccessHacks(const AccessHacks&)=delete;				//Get rid of default copy constructor
	AccessHacks& operator=(const AccessHacks&)=delete;	//Get rid of default copy assignment operator
	AccessHacks(const AccessHacks&&)=delete;			//Get rid of default move constructor
	AccessHacks& operator=(const AccessHacks&&)=delete;	//Get rid of default move assignment operator
	
	static bool EnableDebugPrivileges();
	static bool Wow64DisableWow64FsRedirection();
	static void Wow64RevertWow64FsRedirection();
	static bool ImpersonateLocalSystem();
	static void RevertToSelf();
	
	static bool MakeInstance();
};

#endif //ACCESSHACKS_H