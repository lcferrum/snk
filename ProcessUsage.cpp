#include "ProcessUsage.h"
#include "FilePathRoutines.h"
#include "Common.h"
#include "Extras.h"
#include <iostream>
#include <algorithm>
#include <limits>		//numeric_limits
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

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
	tick_not_tock=!tick_not_tock;
	
	return true;
}

//Assuming that UNICODE_STRING not necessary terminated
PData::PData(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur, ULONG_PTR pid, bool tick_not_tock, UNICODE_STRING name, const std::wstring &path, bool appended, bool system):
	prc_time_dlt(appended?prck_time_cur+prcu_time_cur:0), name(name.Buffer, name.Length/sizeof(wchar_t)), path(path), pid(pid), prck_time_prv(prck_time_cur), prcu_time_prv(prcu_time_cur), crt_time(crt_time_cur), discarded(false), system(system), disabled(false), tick_not_tock(tick_not_tock), ref(NULL)
{
	//If path exists - extract name from it instead using supplied one
	if (!this->path.empty())
		this->name=GetNamePartFromFullPath(this->path);
}

Processes::Processes():
	CAN(), invalid(true), tick_not_tock(false)
{}

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
	for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); ++rit) {
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

void Processes::Synchronize(Processes &ref)
{
	//In both objects CANs should be of equal size
	//In reality they should also be exact copies
	//But we are making this check solely for the loop below not to throw anything
	if (CAN.size()!=ref.CAN.size())
		return;
	
	//Problem with pointers to vector member is that pointer may be invalidated sometime in the future
	//This happens when vector is modified - items added, deleted or reordered
	//So pointers are valid as long as reference vector not modified
	std::vector<PData>::iterator loc_it, ref_it;
	for (loc_it=CAN.begin(), ref_it=ref.CAN.begin(); loc_it!=CAN.end(); ++loc_it, ++ref_it)
		loc_it->SetReference(&(*ref_it));
}

void Processes::ManageProcessList(LstPriMode param_lst_pri_mode, LstSecMode param_lst_sec_mode)
{
	switch (param_lst_pri_mode) {
		case RST_CAN:
			invalid=true;
			break;
		case INV_MASK:
		case CLR_MASK:
			RequestPopulatedCAN();
			for (PData &data: CAN)
				if (param_lst_pri_mode==INV_MASK)
					data.SetDiscarded(!data.GetDiscarded());
				else
					data.SetDiscarded(false);
			break;
		case SHOW_LIST:
			if (param_lst_sec_mode==LST_DUNNO) param_lst_sec_mode=LST_SHOW;
			break;
		case CAN_FFWD:
			RequestPopulatedCAN(false);
			break;
	}
	
	switch (param_lst_sec_mode) {
#if DEBUG>=1
		case LST_DEBUG:
			RequestPopulatedCAN();
			std::wcerr<<L"" __FILE__ ":ManageProcessList:"<<__LINE__<<L": Dumping processes for LST_DEBUG..."<<std::endl;
			DumpProcesses();
			break;
#endif
		case LST_SHOW:
			RequestPopulatedCAN();
			bool avail_found=false;
			//Old fashioned "for" because C++11 ranged-based version can't go in reverse
			for (std::vector<PData>::reverse_iterator rit=CAN.rbegin(); rit!=CAN.rend(); ++rit) {
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
			}
			if (!avail_found) {
				if (ModeAll())
					std::wcout<<L"No processes available"<<std::endl;
				else
					std::wcout<<L"No user processes available"<<std::endl;	
			}
			break;
	}
}

void Processes::RequestPopulatedCAN(bool full)
{
	//Previous version of Processes class kept self_lsid as class member so it had to be freed on destroy
	//This results in non-default copy-constructor which should duplicate self_lsid with GetLengthSid/CopySid
	//To keep things simple (get rid of non-default destructor and copy-constructor) self_lsid is now local variable
	//Because calling EnumProcessUsage outside of this function is currently unneeded functionality

	if (invalid) {
		PSID self_lsid=GetLogonSID(GetCurrentProcess());
		DWORD self_pid=GetCurrentProcessId();
		
		EnumProcessUsage(true, self_lsid, self_pid);
		
		if (full) {
			Sleep(USAGE_TIMEOUT);
			
			CachedNtQuerySystemProcessInformation(NULL, true);
			CachedNtQuerySystemHandleInformation(NULL, true);
			EnumProcessUsage(false, self_lsid, self_pid);
			
			if (ModeRecent())
				SortByRecentlyCreated();
			else
				SortByCpuUsage();
		} else if (ModeRecent()) {
			SortByRecentlyCreated();
		}
		
		FreeLogonSID(self_lsid);
		invalid=false;
	}
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

DWORD Processes::EnumProcessUsage(bool first_time, PSID self_lsid, DWORD self_pid)
{
	SYSTEM_PROCESS_INFORMATION *pspi_all=NULL, *pspi_cur=NULL;
	DWORD ret_size=0;
	DWORD cur_len=0;	//Taking into account that even on x64 ReturnLength of NtQuerySystemInformation is PULONG (i.e. DWORD*), it's safe to assume that process count won't overflow DWORD
	NTSTATUS st;
	std::vector<PData>::iterator pd;
	
	if (first_time) {
		CAN.clear();
		FPRoutines::FillDriveList();
		FPRoutines::FillServiceMap();
	}
	
	tick_not_tock=!tick_not_tock;	//Flipping tick_not_tock
	
	if (!CachedNtQuerySystemProcessInformation(&pspi_all))
		return 0;
	
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
						user=self_lsid?EqualSid(self_lsid, pid_lsid):true;	//If for some reason current Logon SID is unknown - assume that queried process belongs to user (because at least we have opened it with PROCESS_QUERY_(LIMITED_)INFORMATION and got Logon SID)
						FreeLogonSID(pid_lsid);
					}
				}
				
				//It was observed that SYSTEM_PROCESS_INFORMATION.ImageName sometimes has mangled name - with partial or completely omitted extension
				//Process Explorer shows the same thing, so it has something to do with particular processes
				//So it's better to use wildcard in place of extension when killing process using it's name (and not full file path) to circumvent such situation
				CAN.push_back(PData(KERNEL_TIME(pspi_cur), USER_TIME(pspi_cur), pspi_cur->CreateTime.QuadPart, (ULONG_PTR)pspi_cur->UniqueProcessId, tick_not_tock, pspi_cur->ImageName, FPRoutines::GetFilePath(pspi_cur->UniqueProcessId, hProcess, dwDesiredAccess&PROCESS_VM_READ), !first_time, !user));
				
				if (hProcess) CloseHandle(hProcess);
			}
			cur_len++;
		}
		pspi_cur=pspi_cur->NextEntryOffset?(SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pspi_cur+pspi_cur->NextEntryOffset):NULL;
	}
	
	//Unneeded PIDs (which enum period doesn't match current) will be erased
	if (!first_time)
		CAN.erase(std::remove_if(CAN.begin(), CAN.end(), [this](const PData &data){ return data.GetTickNotTock()!=tick_not_tock; }), CAN.end());

	return cur_len;
}

//User SID identifies user that launched process
//But if process was launched with RunAs - it will have SID of the RunAs user
//Only Logon SID will stay the same in this case
//Assuming that SnK is run with admin rights, it's better to use Logon SID to distinguish system processes from user processes
PSID Processes::GetLogonSID(HANDLE hProcess)
{
	HANDLE hToken;
	PSID lsid=NULL;
	
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		if (PTOKEN_GROUPS ptg=GetTokenGroupsInformation(hToken)) {
			DWORD dwLength;
			for (DWORD i=0; i<ptg->GroupCount; i++) 
				if (ptg->Groups[i].Attributes&SE_GROUP_LOGON_ID) {	//It's a Logon SID
					dwLength=GetLengthSid(ptg->Groups[i].Sid);
					lsid=(PSID)new BYTE[dwLength];
					CopySid(dwLength, lsid, ptg->Groups[i].Sid);
					break;
				}
			FreeTokenGroupsInformation(ptg);
		}
		CloseHandle(hToken);
	}
	
	return lsid;
}
