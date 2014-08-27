#include "ProcessUsage.h"
#include "Killers.h"
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

Processes::Processes():
	all(false)
{
	EnumProcessUsage();
	
	/****TEST***
	std::multimap<float, PData>::iterator it;
	for (it=CAN.begin(); it!= CAN.end(); it++)
		std::cout<<(*it).second.pid<<" => "<<(*it).first<<"%"<<std::endl;
	****TEST***/
}

void Processes::SetAll(bool flag)
{
	all=flag;
}

bool Processes::AddBlacklist(bool Full, char* Wcard)
{
	std::multimap<float, PData>::iterator it;
	for (it=CAN.begin(); it!=CAN.end(); it++) {
		if (!it->second.blacklisted&&CheckPath(it->second.pid, Full, Wcard))
			it->second.blacklisted=true;
	}
}

bool Processes::EraseBlacklist()
{
	std::multimap<float, PData>::iterator it;
	for (it=CAN.begin(); it!=CAN.end(); it++)
		it->second.blacklisted=false;
}

bool Processes::FirstValid()
{
	for (;;) {
		if (current_rit==CAN.rend())
			return false;
		if (current_rit->second.disabled||current_rit->second.blacklisted||(all?false:current_rit->second.system))
			current_rit++;
		else
			return true;
	}
}

bool Processes::ResetIteration()
{
	if (CAN.size()) {
		current_rit=CAN.rbegin();
		return FirstValid();
	} else 
		return false;
}

bool Processes::NextIteration()
{
	if (NotEnd()) {
		current_rit++;
		return FirstValid();
	} else
		return false;
}

bool Processes::NotEnd()
{
	return CAN.size()&&current_rit!=CAN.rend();
}

DWORD Processes::GetCurrentPid()
{
	return current_rit->second.pid;
}

void Processes::DisableCurrentPid()
{
	current_rit->second.disabled=true;
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
	float Usage;
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
	
    Usage=(float)(((UserTicks64.QuadPart+KernelTicks64.QuadPart)*100)/StartTicks64.QuadPart);
	PData data={};
	data.pid=PID[index];
	data.system=sys[index];
	CAN.insert(std::pair<float, PData>(Usage, data));

    CloseHandle(hProcess);
}
