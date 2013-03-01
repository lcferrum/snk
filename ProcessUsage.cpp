#include "ProcessUsage.h"
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#define USAGE_TIMEOUT 	1500 	//ms

void FillStatArrays(int index, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST, bool All);
void ComputeStatArrays(int index, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST, std::multimap<float, DWORD> &CAN);

size_t EnumProcessUsage(std::multimap<float, DWORD> &CAN, bool All) {
	DWORD *aProcesses=NULL;
	FILETIME *UserTicks, *KernelTicks, *StartTicks;
	DWORD cbNeeded, Self, cProcesses, cbAllocated=0;
	
	CAN.clear();
	
    do {
		if (aProcesses) delete[] aProcesses;
		cbAllocated+=100;
		aProcesses=new DWORD[cbAllocated];
		if (!EnumProcesses(aProcesses, sizeof(DWORD)*cbAllocated, &cbNeeded)) return 0;
		//printf("needed bytes %d, have %d bytes with %d cells\n", cbNeeded, sizeof(DWORD)*cbAllocated, cbAllocated);
	} while (cbNeeded>=sizeof(DWORD)*cbAllocated);
	
	//printf("we have %d processes\n", cbNeeded/sizeof(DWORD));
	cProcesses=cbNeeded/sizeof(DWORD);
	UserTicks=new FILETIME[cProcesses];
	KernelTicks=new FILETIME[cProcesses];
	StartTicks=new FILETIME[cProcesses];
	Self=GetCurrentProcessId();
	//printf("GetCurrentProcessId() = %d\n", Self);
	
	for (unsigned int i=0; i<cProcesses; i++)
        if((aProcesses[i]!=0)&&(aProcesses[i]!=Self)) {		//0 = idle process
			FillStatArrays(i, aProcesses, UserTicks, KernelTicks, StartTicks, All);
		}
	
	Sleep(USAGE_TIMEOUT);
	
	for (unsigned int i=0; i<cProcesses; i++)
        if((aProcesses[i]!=0)&&(aProcesses[i]!=Self)) {
			ComputeStatArrays(i, aProcesses, UserTicks, KernelTicks, StartTicks, CAN);
		}
	
	delete[] aProcesses;
	delete[] UserTicks;
	delete[] KernelTicks;
	delete[] StartTicks;
	
	return CAN.size();
}

void FillStatArrays(int index, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST, bool All)
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

    if (!EnumProcessModules(hProcess, &fakemod, sizeof(fakemod), &nmod)&&!All) { //ensures that only user-run applications are checked
		PID[index]=0;
		CloseHandle(hProcess);
		return;		
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

void ComputeStatArrays(int index, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST, std::multimap<float, DWORD> &CAN)
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
	CAN.insert(std::pair<float, DWORD>(Usage, PID[index]));

    CloseHandle(hProcess);
}
