#include "ProcessUsage.h"
#include "Extra.h"
#include <iostream>
#include <algorithm> 
#include <winternl.h>	//NT_SUCCESS
//#define NTSTATUS ULONG
//#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#include <stddef.h>		//offsetof
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

unsigned long long int PData::ConvertToUInt64(FILETIME ftime)
{
	ULARGE_INTEGER time64={ftime.dwLowDateTime, ftime.dwHighDateTime};
	return time64.QuadPart;
}

bool PData::ComputePerformance()
{
	if (disabled) return true;
	
	FILETIME tmp_ftime, s_ftime, k_ftime, u_ftime;
	SYSTEMTIME cur_stime;
	//PROCESS_QUERY_LIMITED_INFORMATION/PROCESS_QUERY_INFORMATION is needed for GetProcessTimes
	//PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION are needed for EnumProcessModules
    HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	//HANDLE hProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
								
	if (!hProcess) {
		disabled=true;
		return true;
	}

	if (!GetProcessTimes(hProcess, &tmp_ftime, &s_ftime, &k_ftime, &u_ftime)||
		(GetSystemTime(&cur_stime), false)||
		!SystemTimeToFileTime(&cur_stime, &s_ftime)) {
		disabled=true;
		CloseHandle(hProcess);
		return true;
	}

	perf=((ConvertToUInt64(u_ftime)-u_time64+ConvertToUInt64(k_ftime)-k_time64)*100.0)/(ConvertToUInt64(s_ftime)-s_time64);
	
    CloseHandle(hProcess);
	return false;
}

PData::PData(DWORD pid):
	perf(0), pid(pid), blacklisted(false), system(false), disabled(true)
{
	FILETIME tmp_ftime, s_ftime, k_ftime, u_ftime;
	SYSTEMTIME cur_stime;
    DWORD nmod;
    HMODULE hmod;
	//PROCESS_QUERY_LIMITED_INFORMATION/PROCESS_QUERY_INFORMATION is needed for GetProcessTimes
	//PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION are needed for EnumProcessModules
    HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	//HANDLE hProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
								
	if (!hProcess)
		return;

    if (!EnumProcessModules(hProcess, &hmod, sizeof(hmod), &nmod))	//checks if user-run application
		system=true;
	
	if (!GetProcessTimes(hProcess, &tmp_ftime, &s_ftime, &k_ftime, &u_ftime)||
		(GetSystemTime(&cur_stime), false)||
		!SystemTimeToFileTime(&cur_stime, &s_ftime)) {
		CloseHandle(hProcess);
		return;
	}
	
	u_time64=ConvertToUInt64(u_ftime);
	k_time64=ConvertToUInt64(k_ftime);
	s_time64=ConvertToUInt64(s_ftime);
	disabled=false;

    CloseHandle(hProcess);
}

Processes::Processes():
	CAN(), ModeAll(false), ModeLoop(false), ParamFull(false), ParamClear(false), ArgWcard(NULL)
{
	EnableDebugPrivileges();
	EnumProcessUsage();
	
#ifdef DEBUG
	for (PData &data: CAN)
		std::cout<<data.pid<<" => "<<data.perf<<"% ("<<(data.blacklisted?"b":"_")<<(data.system?"s":"_")<<(data.disabled?"d)":"_)")<<std::endl;
#endif
}

bool Processes::ApplyToProcesses(std::function<bool(DWORD)> mutator)
{
	bool applied=false;
	
	//Old fashioned for, so not to use lambdas with returns
	for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (!rit->disabled&&!rit->blacklisted&&!(ModeAll?false:rit->system)&&mutator(rit->pid)) {
			applied=true;
			rit->disabled=true;
			if (!ModeLoop) break;
		}
	}
	
	//A hack to make for_each breackable - use find_if instead
	//If lambda returns true - find_if breaks
	/*std::find_if(CAN.rbegin(), CAN.rend(), [this, &applied, mutator](PData &data){
		if (!data.disabled&&!data.blacklisted&&!(all?false:data.system)&&mutator(data.pid)) {
			applied=true;
			data.disabled=true;
			return !loop;
		} else
			return false;
	});*/
	
	return applied;
}

void Processes::ModifyBlacklist()
{
	if (ParamClear) {
		if (ParamFull) std::cout<<"Warning: \"clear\" parameter is set - \"full\" parameter will be ignored!"<<std::endl;
		for (PData &data: CAN) {
			data.blacklisted=false;
		}
	} else
		for (PData &data: CAN) {
			if (!data.blacklisted&&CheckPath(data.pid, ParamFull, ArgWcard))
				data.blacklisted=true;
		}
		
#ifdef DEBUG
	for (PData &data: CAN)
		std::cout<<data.pid<<" => "<<data.perf<<"% ("<<(data.blacklisted?"b":"_")<<(data.system?"s":"_")<<(data.disabled?"d)":"_)")<<std::endl;
#endif
}

void Processes::ClearParamsAndArgs()
{
	ParamClear=false;
	ParamFull=false;
	ArgWcard=NULL;
}

void Processes::EnumProcessUsage() 
{
	DWORD *aProcesses=NULL;
	DWORD Self=GetCurrentProcessId();
	DWORD cur_len=0;
	DWORD ret_size=0;
	
	CAN.clear();

	//EnumProcesses returns actual read size in pBytesReturned and treats operation succesfull even if buffer size was smaller than needed
	//We can tell that we read all information available only if actual read size is smaller than allocated buffer size
	while (ret_size>=cur_len*sizeof(DWORD)) {
		delete[] aProcesses;
		aProcesses=new DWORD[(cur_len+=64)];
		if (!EnumProcesses(aProcesses, cur_len*sizeof(DWORD), &ret_size)) return;
	}

	for (int i=0; i<ret_size/sizeof(DWORD); i++)
		if((aProcesses[i]!=0)&&(aProcesses[i]!=Self))	//0 = idle process
			CAN.push_back(PData(aProcesses[i]));

	delete[] aProcesses;
	
	Sleep(USAGE_TIMEOUT);
	
	//Unaccessible elements will be erased, while performance will be calculated for accessible ones
	CAN.erase(std::remove_if(CAN.begin(), CAN.end(), [](PData &data){ return data.ComputePerformance(); }), CAN.end());
	
	//PIDs were added to the CAN in the creation order (last created PIDs are at the end of the list)
	//Using stable_sort we preserve this original order for PIDs with equal CPU load
	//Compare function sorts PIDs in ascending order so reverse iterator is used for accessing PIDs
	//Considering sorting order and stable sort algorithm we will first get PIDs with highest CPU load
	//and, in the case of equal CPU load, last created PID will be selected
	std::stable_sort(CAN.begin(), CAN.end());
}

#define SE_DEBUG_PRIVILEGE (20L)		//Grants r/w access to any process
#define SE_BACKUP_PRIVILEGE (17L)		//Grants read access to any file
#define SE_LOAD_DRIVER_PRIVILEGE (10L)	//Grants device driver load/unload rights [currently no use]
#define SE_RESTORE_PRIVILEGE (18L)		//Grants write access to any file
#define SE_SECURITY_PRIVILEGE (8L)		//Grants r/w access to audit and security messages [no use]
	
void Processes::EnableDebugPrivileges()
{
    HANDLE tokenHandle;
	
	//Privileges similar to Process Explorer
	DWORD needed_privs[]={SE_DEBUG_PRIVILEGE, SE_BACKUP_PRIVILEGE, SE_LOAD_DRIVER_PRIVILEGE,
							SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE};

    if (NT_SUCCESS(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle))) {
        PTOKEN_PRIVILEGES privileges=(PTOKEN_PRIVILEGES)new char[offsetof(TOKEN_PRIVILEGES, Privileges)+sizeof(LUID_AND_ATTRIBUTES)*sizeof(needed_privs)/sizeof(DWORD)];

        privileges->PrivilegeCount=0;
        for (DWORD priv: needed_privs) {
			privileges->Privileges[privileges->PrivilegeCount].Attributes=SE_PRIVILEGE_ENABLED;
            privileges->Privileges[privileges->PrivilegeCount].Luid.HighPart=0;
			privileges->Privileges[privileges->PrivilegeCount].Luid.LowPart=priv;
			privileges->PrivilegeCount++;
        }

        AdjustTokenPrivileges(tokenHandle, FALSE, privileges, 0, NULL, NULL);
		
		delete[] privileges;
        CloseHandle(tokenHandle);
    }
}
