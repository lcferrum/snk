#include "ProcessUsage.h"
#include "FilePathRoutines.h"
#include "Common.h"
#include "Extras.h"
#include <iostream>
#include <algorithm>
#include <cstddef>		//offsetof
#include <limits>		//numeric_limits
#include <winternl.h>	//NT_SUCCESS, SYSTEM_PROCESS_INFORMATION, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, SYSTEM_BASIC_INFORMATION, UNICODE_STRING
#include <ntstatus.h>	//STATUS_INFO_LENGTH_MISMATCH
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

extern pNtQuerySystemInformation fnNtQuerySystemInformation;
extern pWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection;
extern pWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection;

#ifdef USE_CYCLE_TIME
#define USER_TIME(pspi) (ULONGLONG)pspi->Reserved[2].QuadPart	//SYSTEM_PROCESS_INFORMATION.CycleTime, available since Win 7
#define KERNEL_TIME(pspi) 0
#else
#define USER_TIME(pspi) pspi->UserTime.QuadPart
#define KERNEL_TIME(pspi) pspi->KernelTime.QuadPart
#endif

bool PData::ComputeDelta(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur)
{
	if (crt_time!=crt_time_cur) return false;
	
	prc_time_dlt=(prck_time_cur-prck_time_prv)+(prcu_time_cur-prcu_time_prv);	//Won't check for overflow here because delta should be really small for both process times, assuming short query interval
	prck_time_prv=prck_time_cur;
	prcu_time_prv=prcu_time_cur;
	odd_enum=!odd_enum;
	
	return true;
}

//Assuming that UNICODE_STRING not necessary terminated
//Complex expression in prc_time_dlt initialization is (paranoid) overflow check
PData::PData(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur, ULONG_PTR pid, bool odd_enum, UNICODE_STRING name, const std::wstring &path, bool system):
	prc_time_dlt((prck_time_cur>std::numeric_limits<ULONGLONG>::max()-prcu_time_cur)?std::numeric_limits<ULONGLONG>::max():prck_time_cur+prcu_time_cur), name(name.Buffer, name.Length/sizeof(wchar_t)), path(path), pid(pid), prck_time_prv(prck_time_cur), prcu_time_prv(prcu_time_cur), crt_time(crt_time_cur), discarded(false), system(system), disabled(false), odd_enum(odd_enum)
{
	//If path exists - extract name from it instead using supplied one
	if (!this->path.empty()) {
		wchar_t fname[_MAX_FNAME];
		wchar_t ext[_MAX_EXT];
		_wsplitpath(this->path.c_str(), NULL, NULL, fname, ext);
		this->name.clear();
		this->name+=fname;
		this->name+=ext;
	}
}

Processes::Processes():
	CAN(), self_pid(GetCurrentProcessId()), self_lsid(GetLogonSID(GetCurrentProcess()))
{
	if (fnWow64DisableWow64FsRedirection) fnWow64DisableWow64FsRedirection(&wow64_fs_redir);	//So GetLongPathName and GetFileAttributes uses correct path
	EnableDebugPrivileges();	//Will set debug privileges (administrator privileges should be already present for this to actually work)
	CoInitialize(NULL);			//COM is needed for GetLongPathName implementation from newapis.h
		
	EnumProcessUsage();
}

Processes::~Processes()
{
	FreeLogonSID(self_lsid);
	CoUninitialize();
	if (fnWow64RevertWow64FsRedirection) fnWow64RevertWow64FsRedirection(wow64_fs_redir);
}

void Processes::DumpProcesses()
{
#if DEBUG>=1
	for (PData &data: CAN)
		std::wcerr<<data.GetPID()<<L" => "<<data.GetDelta()<<L" ("<<(data.GetSystem()?L"s":L"_")<<(data.GetDiscarded()?L"d":L"_")<<(data.GetDisabled()?L"D) ":L"_) ")<<data.GetName()<<L" ["<<data.GetPath()<<L"]"<<std::endl;
#endif
}

bool Processes::ApplyToProcesses(std::function<bool(ULONG_PTR, const std::wstring&, const std::wstring&, bool)> mutator)
{
	bool applied=false;
	
	//Old fashioned "for" because C++11 ranged-based version can't go in reverse
	for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (!rit->GetDisabled()&&!rit->GetDiscarded()&&!(ModeAll()?false:rit->GetSystem())&&mutator(rit->GetPID(), rit->GetName(), rit->GetPath(), applied)) {
			applied=true;
			if (!ModeBlank()) rit->SetDisabled(true);
			if (ModeBlacklist()) rit->SetDiscarded(true);
			if (ModeWhitelist()) rit->SetDiscarded(false);
			if (!ModeLoop()) break;
		} else {
			if (ModeWhitelist()) rit->SetDiscarded(true);
		}
	}
	
	return applied;
}

void Processes::Synchronize(bool param_disabled, std::function<bool(ULONG_PTR)> mutator)
{
	//Old fashioned "for" because C++11 ranged-based version can't go in reverse
	for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (rit->GetDisabled()==param_disabled&&mutator(rit->GetPID())) {
			rit->SetDisabled(true);
			break;
		}
	}
}

void Processes::ManageProcessList(LstMode param_lst_mode)
{
#if DEBUG>=1
	if (param_lst_mode==LST_DEBUG) {
		std::wcerr<<L"" __FILE__ ":ManageProcessList:"<<__LINE__<<L": Dumping processes for LST_DEBUG..."<<std::endl;
		DumpProcesses();
		return;
	}
#endif

	bool avail_found=false;

	//Old fashioned "for" because C++11 ranged-based version can't go in reverse
	for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		switch (param_lst_mode) {
			case LST_SHOW:
				if (!rit->GetDisabled()&&!rit->GetDiscarded()&&!(ModeAll()?false:rit->GetSystem())) {
					if (!avail_found) {
						if (ModeAll())
							std::wcout<<L"Available processes:"<<std::endl;
						else
							std::wcout<<L"Available user processes:"<<std::endl;	
						avail_found=true;
					}
					std::wcout<<rit->GetPID()<<L" ("<<rit->GetName()<<L")"<<std::endl;
				}
				break;
			case INV_MASK:
				if (rit->GetDiscarded())
					rit->SetDiscarded(false);
				else
					rit->SetDiscarded(true);
				break;
			case CLR_MASK:
				rit->SetDiscarded(false);
				break;
			default:	//Added to silence clang's -Wswitch warning
				break;
		}
	}
	
	if (param_lst_mode==LST_SHOW&&!avail_found) {
		if (ModeAll())
			std::wcout<<L"No processes available"<<std::endl;
		else
			std::wcout<<L"No user processes available"<<std::endl;	
	}
}

void Processes::EnumProcessUsage() 
{
	EnumProcessTimes(true);
	
	Sleep(USAGE_TIMEOUT);
	
	EnumProcessTimes(false);
	
	SortByCpuUsage();
}

void Processes::SortByCpuUsage()
{
	//This is default sorting
	//In EnumProcessTimes PIDs are added to the CAN in the creation order (last created PIDs are at the end of the list)
	//SortByRecentlyCreated also sorts PIDs in creation order using process creation time
	//Using stable_sort we preserve this order for PIDs with equal CPU load
	//Compare function sorts PIDs in ascending order so reverse iterator is used for accessing PIDs
	//Considering sorting order and stable sort algorithm we will first get PIDs with highest CPU load
	//And, in the case of equal CPU load, last created PID will be selected
	std::stable_sort(CAN.begin(), CAN.end());
	
#if DEBUG>=1
	std::wcerr<<L"" __FILE__ ":SortByCpuUsage:"<<__LINE__<<L": Dumping processes after CPU usage sort..."<<std::endl;
	DumpProcesses();
#endif
}

void Processes::SortByRecentlyCreated()
{
	//Sort PIDs in creation order using process creation time
	//Conforming to reverse accessing of CAN, PIDs are sorted in ascending order so last created PIDs are at the end of the list
	std::sort(CAN.begin(), CAN.end(), [](const PData &left, const PData &right){ return left.GetCrtTime()<right.GetCrtTime(); });
	
#if DEBUG>=1
	std::wcerr<<L"" __FILE__ ":SortByRecentlyCreated:"<<__LINE__<<L": Dumping processes after recently created sort..."<<std::endl;
	DumpProcesses();
#endif
}

DWORD Processes::EnumProcessTimes(bool first_time)
{
	SYSTEM_PROCESS_INFORMATION *pspi_all=NULL, *pspi_cur=NULL;
	DWORD ret_size=0;
	DWORD cur_len=0;	//Taking into account that even on x64 ReturnLength of NtQuerySystemInformation is PULONG (i.e. DWORD*), it's safe to assume that process count won't overflow DWORD
	NTSTATUS st;
	std::vector<PData>::iterator pd;
	
	if (first_time) {
		CAN.clear();
		FPRoutines::FillDriveMap();
		FPRoutines::FillServiceMap();
	}
	
	odd_enum=!odd_enum;	//Flipping odd_enum
	
	if (!fnNtQuerySystemInformation) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":EnumProcessTimes:"<<__LINE__<<L": NtQuerySystemInformation not found!"<<std::endl;
#endif
		return 0;
	}

	//NtQuerySystemInformation before XP returns actual read size in ReturnLength rather than needed size
	//NtQuerySystemInformation(SystemProcessInformation) retreives not only SYSTEM_PROCESS_INFORMATION structure but also an array of SYSTEM_THREAD structures and UNICODE_STRING with name for each process
	//So we can't tell for sure how many bytes will be needed to store information for each process because thread count and name length varies between processes
	//Each iteration buffer size is increased by 4KB
	//For SYSTEM_PROCESS_INFORMATION buffer can be really large - like several hundred kilobytes
	do {
		delete[] (BYTE*)pspi_all;
		pspi_all=(SYSTEM_PROCESS_INFORMATION*)new BYTE[(cur_len+=4096)];
	} while ((st=fnNtQuerySystemInformation(SystemProcessInformation, pspi_all, cur_len, &ret_size))==STATUS_INFO_LENGTH_MISMATCH);
	
	if (!NT_SUCCESS(st)||!ret_size) {
		delete[] (BYTE*)pspi_all;
		return 0;
	}
	
	cur_len=0;
	pspi_cur=pspi_all;
	while (pspi_cur) {
		if (pspi_cur->UniqueProcessId&&self_pid!=(ULONG_PTR)pspi_cur->UniqueProcessId&&(ULONG_PTR)pspi_cur->UniqueProcessId!=4&&(ULONG_PTR)pspi_cur->UniqueProcessId!=2&&(ULONG_PTR)pspi_cur->UniqueProcessId!=8) {	//If it's not current process' PID or idle (PID 0) or system process (PID 2 on NT4, PID 8 on 2000, PID 4 on everything else)
			if (first_time||	//If it's the first time pass - don't bother checking PIDs, just add everything
				(pd=std::find(CAN.begin(), CAN.end(), (ULONG_PTR)pspi_cur->UniqueProcessId))==CAN.end()||	//If PID not found - add it
				!pd->ComputeDelta(KERNEL_TIME(pspi_cur), USER_TIME(pspi_cur), pspi_cur->CreateTime.QuadPart)) {	//If PID is found - calculate delta or, in case it's a wrong PID, add it
				bool user=false;
				DWORD dwDesiredAccess=PROCESS_QUERY_INFORMATION|PROCESS_VM_READ;
				HANDLE hProcess=OpenProcessWrapper((ULONG_PTR)pspi_cur->UniqueProcessId, dwDesiredAccess);
				
				//If we can't open process with PROCESS_QUERY_(LIMITED_)INFORMATION|(PROCESS_VM_READ) rights or can't get it's Logon SID - assume that it's a non-user process
				if (hProcess) {
					if (PSID pid_lsid=GetLogonSID(hProcess)) {
						user=self_lsid?EqualSid(self_lsid, pid_lsid):true;	//If for some reason current Logon SID is unknown - assume that queried process is user one (because at least we have opened it with PROCESS_QUERY_(LIMITED_)INFORMATION and got Logon SID)
						FreeLogonSID(pid_lsid);
					}
				}
				
				//It was observed that SYSTEM_PROCESS_INFORMATION.ImageName sometimes has mangled name - with partial or completely omitted extension
				//Process Explorer shows the same thing, so it has something to do with particular processes
				//So it's better to use wildcard in place of extension when killing process using it's name (and not full file path) to circumvent such situation
				CAN.push_back(PData(KERNEL_TIME(pspi_cur), USER_TIME(pspi_cur), pspi_cur->CreateTime.QuadPart, (ULONG_PTR)pspi_cur->UniqueProcessId, odd_enum, pspi_cur->ImageName, FPRoutines::GetFilePath(pspi_cur->UniqueProcessId, hProcess, dwDesiredAccess&PROCESS_VM_READ), !user));
				
				if (hProcess) CloseHandle(hProcess);
			}
			cur_len++;
		}
		pspi_cur=pspi_cur->NextEntryOffset?(SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pspi_cur+pspi_cur->NextEntryOffset):NULL;
	}
	
	//Unneeded PIDs (which enum period doesn't match current) will be erased
	if (!first_time)
		CAN.erase(std::remove_if(CAN.begin(), CAN.end(), [this](const PData &data){ return data.GetOddEnum()!=odd_enum; }), CAN.end());

	delete[] (BYTE*)pspi_all;
	return cur_len;
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

//User SID identifies user that launched process. But if process was launched with RunAs - it will have SID of the RunAs user.
//Only Logon SID will stay the same in this case.
//Assuming that SnK is run with admin rights, it's better to use Logon SID to distinguish system processes from user processes.
PSID Processes::GetLogonSID(HANDLE hProcess)
{
	HANDLE hToken;
	DWORD dwLength=0;
	PTOKEN_GROUPS ptg;
	PSID lsid=NULL;
	
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return NULL;

	//If GetTokenInformation doesn't fail with ERROR_INSUFFICIENT_BUFFER - something went wrong
	if (GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLength)||GetLastError()!=ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(hToken);
		return NULL;
	}
	
	ptg=(PTOKEN_GROUPS)new BYTE[dwLength];
	
	if (GetTokenInformation(hToken, TokenGroups, (LPVOID)ptg, dwLength, &dwLength)) {
		for (DWORD i=0; i<ptg->GroupCount; i++) 
			if (ptg->Groups[i].Attributes&SE_GROUP_LOGON_ID) {	//It's a Logon SID
				dwLength=GetLengthSid(ptg->Groups[i].Sid);
				lsid=(PSID)new BYTE[dwLength];
				CopySid(dwLength, lsid, ptg->Groups[i].Sid);
				break;
			}
	}
	
	CloseHandle(hToken);
	delete[] (BYTE*)ptg;
	return lsid;
}

void Processes::FreeLogonSID(PSID lsid)
{
	delete[] (BYTE*)lsid;
}
