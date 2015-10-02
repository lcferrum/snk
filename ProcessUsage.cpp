#include "ProcessUsage.h"
#include "Extra.h"
#include <algorithm> 
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

Processes::Processes():
	CAN(), ModeAll(false), ModeLoop(false), ParamFull(false), ParamClear(false), ArgWcard(NULL)
{
	EnumProcessUsage();
	
	/****TEST***
	std::vector<PData>::iterator it;
	for (it=CAN.begin(); it!= CAN.end(); it++)
		std::cout<<it->pid<<" => "<<it->perf<<"%"<<std::endl;
	****TEST***/
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
	FILETIME *UserTicks, *KernelTicks, *StartTicks;
	bool *System;
	DWORD cbNeeded, Self, cProcesses, cbAllocated=0;
	
	CAN.clear();
	
    do {
		if (aProcesses) delete[] aProcesses;
		cbAllocated+=100;
		aProcesses=new DWORD[cbAllocated];
		if (!EnumProcesses(aProcesses, sizeof(DWORD)*cbAllocated, &cbNeeded)) return;
		//printf("needed bytes %d, have %d bytes with %d cells\n", cbNeeded, sizeof(DWORD)*cbAllocated, cbAllocated);
	} while (cbNeeded>=sizeof(DWORD)*cbAllocated);
	
	//printf("we have %d processes\n", cbNeeded/sizeof(DWORD));
	cProcesses=cbNeeded/sizeof(DWORD);
	UserTicks=new FILETIME[cProcesses];
	KernelTicks=new FILETIME[cProcesses];
	StartTicks=new FILETIME[cProcesses];
	System=new bool[cProcesses];
	Self=GetCurrentProcessId();
	//printf("GetCurrentProcessId() = %d\n", Self);
	
	for (unsigned int i=0; i<cProcesses; i++)
        if((aProcesses[i]!=0)&&(aProcesses[i]!=Self)) {		//0 = idle process
			FillStatArrays(i, System, aProcesses, UserTicks, KernelTicks, StartTicks);
		}
	
	Sleep(USAGE_TIMEOUT);
	
	for (unsigned int i=0; i<cProcesses; i++)
        if((aProcesses[i]!=0)&&(aProcesses[i]!=Self)) {
			ComputeStatArrays(i, System, aProcesses, UserTicks, KernelTicks, StartTicks);
		}
	
	//PIDs were added to the CAN in the creation order (last created PIDs are at the end of the list)
	//Using stable_sort we preserve this original order for PIDs with equal CPU load
	//Compare function sorts PIDs in ascending order so reverse iterator is used for accessing PIDs
	//Considering sorting order and stable sort algorithm we will first get PIDs with highest CPU load
	//and, in the case of equal CPU load, last created PID will be selected
	std::stable_sort(CAN.begin(), CAN.end());
	
	delete[] aProcesses;
	delete[] UserTicks;
	delete[] KernelTicks;
	delete[] StartTicks;
	delete[] System;
}

void Processes::FillStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST)
{
	FILETIME temp1, temp2;
	SYSTEMTIME current;
    DWORD nmod;
    HMODULE fakemod;
    HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|
                                PROCESS_VM_READ,
                                FALSE, PID[index]);
								
	if (!hProcess) {
		PID[index]=0;
		return;
	}

    if (!EnumProcessModules(hProcess, &fakemod, sizeof(fakemod), &nmod)) { //checks if user-run application
		sys[index]=true;
    }
	
	if (!GetProcessTimes(hProcess, &temp1, &temp2, KT+index, UT+index)) {
		PID[index]=0;
		CloseHandle(hProcess);
		return;
	}
	
	GetSystemTime(&current);
	if (!SystemTimeToFileTime(&current, ST+index)) {
		PID[index]=0;
	}	

    CloseHandle(hProcess);
}

void Processes::ComputeStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST)
{
	FILETIME temp1, temp2, tempK, tempU, tempS;
	ULARGE_INTEGER Left64, Right64, UserTicks64, KernelTicks64, StartTicks64;
	SYSTEMTIME current;
    HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|
                                PROCESS_VM_READ,
                                FALSE, PID[index]);
								
	if (!hProcess) {
		return;
	}
	
	if (!GetProcessTimes(hProcess, &temp1, &temp2, &tempK, &tempU)) {
		CloseHandle(hProcess);
		return;
	}
	
	GetSystemTime(&current);
	if (!SystemTimeToFileTime(&current, &tempS)) {
		CloseHandle(hProcess);
		return;
	}	
	
	Left64.LowPart=tempS.dwLowDateTime;
	Left64.HighPart=tempS.dwHighDateTime;
	Right64.LowPart=ST[index].dwLowDateTime;
	Right64.HighPart=ST[index].dwHighDateTime;
	StartTicks64.QuadPart=Left64.QuadPart-Right64.QuadPart;
	
	Left64.LowPart=tempU.dwLowDateTime;
	Left64.HighPart=tempU.dwHighDateTime;
	Right64.LowPart=UT[index].dwLowDateTime;
	Right64.HighPart=UT[index].dwHighDateTime;
	UserTicks64.QuadPart=Left64.QuadPart-Right64.QuadPart;
	
	Left64.LowPart=tempK.dwLowDateTime;
	Left64.HighPart=tempK.dwHighDateTime;
	Right64.LowPart=KT[index].dwLowDateTime;
	Right64.HighPart=KT[index].dwHighDateTime;
	KernelTicks64.QuadPart=Left64.QuadPart-Right64.QuadPart;
	
	PData data={};
	data.pid=PID[index];
	data.system=sys[index];
	data.perf=((UserTicks64.QuadPart+KernelTicks64.QuadPart)*100.0)/StartTicks64.QuadPart;
	CAN.push_back(data);

    CloseHandle(hProcess);
}
