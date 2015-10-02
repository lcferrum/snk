#include "Extra.h"
#include <iostream>

typedef HWND (WINAPI *pNtUserHungWindowFromGhostWindow)(HWND hwndGhost);
pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow;

HINSTANCE g_hUser32;

bool Load_Extra() {
	g_hUser32=NULL;
	g_hUser32=LoadLibrary("user32.dll");

	if (!g_hUser32) return false;

	fnNtUserHungWindowFromGhostWindow=(pNtUserHungWindowFromGhostWindow)GetProcAddress(g_hUser32, "HungWindowFromGhostWindow");

	if (!fnNtUserHungWindowFromGhostWindow) return false;

	return true;
}

void UnLoad_Extra() {
	if (g_hUser32) FreeLibrary(g_hUser32);
}

HWND extraUserHungWindowFromGhostWindow(HWND hwndGhost) {
	if (fnNtUserHungWindowFromGhostWindow) {
		return fnNtUserHungWindowFromGhostWindow(hwndGhost);
	} else return NULL;
}

void checkUserHungWindowFromGhostWindow() {
	if (!fnNtUserHungWindowFromGhostWindow)
		std::cerr<<"HungWindowFromGhostWindow not found in user32.dll!"<<std::endl;
}

//WildcardCmp: 
//Written by Jack Handy <jakkhandy@hotmail.com>
//http://www.codeproject.com/Articles/1088/Wildcard-string-compare-globbing
int WildcardCmp(const char* wild, const char* string) {
	const char *cp=NULL, *mp=NULL;

	while ((*string)&&(*wild!='*')) {
		if ((tolower(*wild)!=tolower(*string))&&(*wild!='?'))
			return 0;
		wild++;
		string++;
	}

	while (*string) {
		if (*wild=='*') {
			if (!*++wild)
				return 1;
			mp=wild;
			cp=string+1;
		} else if ((tolower(*wild)==tolower(*string))||(*wild=='?')) {
			wild++;
			string++;
		} else {
			wild=mp;
			string=cp++;
		}
	}

	while (*wild=='*')
		wild++;
	
	return !*wild;
}

bool CheckPath(DWORD PID, bool Full, char* Wcard) {
	char ProcName[MAX_PATH] = "";
	
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_TERMINATE,
								FALSE, PID);
								
	if (!hProcess) return false;
								
	if (Full) GetModuleFileNameEx(hProcess, NULL, ProcName, sizeof(ProcName));	
		else GetModuleBaseName(hProcess, NULL, ProcName, sizeof(ProcName));	
	
	CloseHandle(hProcess);
	
	return WildcardCmp(Wcard, ProcName);
}

bool CheckName(DWORD PID, char** Wcards) {
	HMODULE *aModules=NULL;
	DWORD cbNeeded, cModules, cbAllocated=0;
	HANDLE hProcess;
	bool Found=false;
	
	hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|
                         PROCESS_VM_READ,
                         FALSE, PID);
						 
	if (!hProcess) return false;

    do {
		if (aModules) delete[] aModules;
		cbAllocated+=150;
		aModules=new HMODULE[cbAllocated];
		if (!EnumProcessModules(hProcess, aModules, sizeof(HMODULE)*cbAllocated, &cbNeeded)) {
			delete[] aModules;
			CloseHandle(hProcess);
			return false;
		}
		//printf("needed bytes %d, have %d bytes with %d cells\n", cbNeeded, sizeof(HMODULE)*cbAllocated, cbAllocated);
	} while (cbNeeded>=sizeof(DWORD)*cbAllocated);
			
	cModules=cbNeeded/sizeof(HMODULE);
	
	for (unsigned int i=0; i<cModules; i++) {
		char szModName[MAX_PATH];
		
		if (GetModuleBaseName(hProcess, aModules[i], szModName, sizeof(szModName))) {
			//printf("\t%s (0x%08X)\n", szModName, aModules[i] );
			
			int ii=0;
			while (Wcards[ii]) {
				if (Found=WildcardCmp(Wcards[ii], szModName)) break;
				ii++;
			}
		}
		
		if (Found) break;
	}
	
	delete[] aModules;	
	CloseHandle(hProcess);
	
	return Found;
}
