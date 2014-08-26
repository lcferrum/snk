#include "Killers.h"
#include "Extra.h"
#include <stdio.h>
#include <iostream>
#include <set>
#include <psapi.h>

#define INR_TIMEOUT					5000 //ms

struct LANGANDCODEPAGE {
	WORD	wLanguage;
	WORD	wCodePage;
};

struct ENUM_CELL_FSC {
	DWORD	dispW;
	DWORD	dispH;
	bool	taskbar_topmost;
	std::multiset<DWORD> *pWndPid;
};

struct ENUM_CELL_INR {
	char mode;				//H - IsHungAppWindow, M - SendMessageTimeout, G - Ghost
	std::multiset<DWORD> *pWndPid;
};

bool CheckDescription(DWORD PID, char** Desc, char** Item);
/**** CheckDescription syntax *****
char* Desc[]={"I1_word1 OR", NULL, "(I1_word2A AND", "I1_word2B)", NULL, NULL,	"I2A_word1", NULL, NULL, 	"I2B_word1", NULL, NULL};
char* Item[]={"Item1 OR", NULL,													"(Item2A AND",				"Item2B)", NULL, NULL};
**********************************/
bool CheckPath(DWORD PID, bool Full, char* Wcard);
/******** CheckPath syntax ********
* - zero or more characters
? - one character
**********************************/
bool CheckName(DWORD PID, char** Wcards);
/******** CheckName syntax ********
char* Wcards[]={"Wcard1 OR", "Wcard2", NULL};	
* - zero or more characters
? - one character
**********************************/
BOOL CALLBACK EnumFullscreenApps(HWND WinHandle, LPARAM Param);
BOOL CALLBACK EnumFullscreenAll(HWND WinHandle, LPARAM Param);
BOOL CALLBACK EnumNotResponding(HWND WinHandle, LPARAM Param);

void KillProcess(DWORD PID, bool Aim) {
	char ProcName[MAX_PATH] = "";
	
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_TERMINATE,
								FALSE, PID);
								
	if (!hProcess) {
		std::cout<<"Troublemaker process: "<<PID<<" (process can't be quired)"<<std::endl;
		return;
	}
								
	GetModuleBaseName(hProcess, NULL, ProcName, sizeof(ProcName));	
	
	if (Aim) {
		std::cout<<"Troublemaker process: "<<PID<<" ("<<ProcName<<")"<<std::endl;
	} else {
		TerminateProcess(hProcess, 1);
	
		std::cout<<"Process "<<PID<<" ("<<ProcName<<") killed!"<<std::endl;
	}
	
	CloseHandle(hProcess);
}

bool KillByCpu(std::multimap<float, DWORD> &CAN, bool Aim) {
	DWORD KillPid;
	
	if (!CAN.empty()) {
		std::cout<<"Process with highest cpu usage FOUND!"<<std::endl;
		KillPid=(*CAN.rbegin()).second;
		KillProcess(KillPid, Aim);
		CAN.erase(CAN.rbegin());
		return true;
	} else {
		std::cout<<"Process with highest cpu usage NOT found!"<<std::endl;
		return false;
	}
}

bool KillByOgl(std::multimap<float, DWORD> &CAN, bool Simple, bool Soft, bool Aim) {
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	char* descA[]={"OpenGL", NULL, "MiniGL", NULL, NULL,	"http://www.mesa3d.org", NULL, NULL};
	char* itemA[]={"FileDescription", NULL,					"Contact", NULL, NULL};
	
	char* descB[]={"OpenGL", NULL, NULL, 	"SwiftShader", NULL, "DLL", NULL, NULL};
	char* itemB[]={"FileDescription", 		"FileDescription", NULL, NULL};
	
	char* descC[]={"OpenGL", NULL, NULL, 	"Driver", NULL, "ICD", NULL, "MCD", NULL, NULL};
	char* itemC[]={"FileDescription", 		"FileDescription", NULL, NULL};
	
	char* wcrdA[]={"opengl*.dll", "3dfx*gl*.dll", NULL};
	
	char* wcrdB[]={"osmesa32.dll", NULL};
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (Soft?
			(Simple?CheckName((*rit).second, wcrdB):CheckDescription((*rit).second, descB, itemB)&&!CheckDescription((*rit).second, descC, itemC)):
			(Simple?CheckName((*rit).second, wcrdA):CheckDescription((*rit).second, descA, itemA))) {
			std::cout<<"Process that uses OpenGL FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}
	
	std::cout<<"Process that uses OpenGL NOT found!"<<std::endl;
	return false;
}

bool KillByD3d(std::multimap<float, DWORD> &CAN, bool Simple, bool Soft, bool Aim) {
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	//"DirectX Driver" - rare case used in description of
	//3Dfx (and it's vendors) driver bundle
	char* descA[]={"Direct3D", NULL, "DirectX Driver", NULL, NULL};
	char* itemA[]={"FileDescription", NULL, NULL};
	
	char* descB[]={"Direct3D", NULL, NULL, 	"SwiftShader", NULL, "Reference", NULL, "Rasterizer", NULL, NULL};
	char* itemB[]={"FileDescription", 		"FileDescription", NULL, NULL};
	
	char* wcrdA[]={"d3d*.dll", NULL};
	
	char* wcrdB[]={"d3d*ref.dll", "d3d*warp.dll", NULL};
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (Soft?
			(Simple?CheckName((*rit).second, wcrdB):CheckDescription((*rit).second, descB, itemB)):
			(Simple?CheckName((*rit).second, wcrdA):CheckDescription((*rit).second, descA, itemA))) {
			std::cout<<"Process that uses Direct3D FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}

	std::cout<<"Process that uses Direct3D NOT found!"<<std::endl;
	return false;
}

bool KillByInr(std::multimap<float, DWORD> &CAN, char Mode, bool Aim) {
	ENUM_CELL_INR EnumCell;
	std::multiset<DWORD> WND_PID;
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;

	if (Mode=='G') checkUserHungWindowFromGhostWindow();
	
	EnumCell.mode=Mode;
	EnumCell.pWndPid=&WND_PID;
	EnumWindows((WNDENUMPROC)EnumNotResponding, (LPARAM)&EnumCell);

	/****TEST***
	std::multiset<DWORD>::iterator it;
	for (it=WND_PID.begin(); it!= WND_PID.end(); it++)
		printf("%d\n", *it);
	****TEST***/
	
	if (WND_PID.empty()) {
		std::cout<<"Process that is not responding NOT found!"<<std::endl;
		return false;
	}
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (WND_PID.find((*rit).second)!=WND_PID.end()) {
			std::cout<<"Process that is not responding FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}
	
	std::cout<<"Process that is not responding NOT found!"<<std::endl;
	return false;
}

bool KillByD2d(std::multimap<float, DWORD> &CAN, bool Simple, bool Strict, bool Aim) {
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	char* descA[]={"DirectDraw", NULL, NULL};
	char* itemA[]={"FileDescription", NULL, NULL};
	
	char* descB[]={"OpenGL", NULL, "Direct3D", NULL, "DirectX Driver", NULL, "Glide", "3Dfx Interactive", NULL, NULL};
	char* itemB[]={"FileDescription", NULL, NULL};
	
	char* wcrdA[]={"ddraw.dll", NULL};
	
	char* wcrdB[]={"opengl*.dll", "3dfx*gl*.dll", "d3d*.dll", "glide*.dll", NULL};
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if ((Simple?CheckName((*rit).second, wcrdA):CheckDescription((*rit).second, descA, itemA))&&
			!(Strict?(Simple?CheckName((*rit).second, wcrdB):CheckDescription((*rit).second, descB, itemB)):false)) {
			std::cout<<"Process that uses DirectDraw FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}
	
	std::cout<<"Process that uses DirectDraw NOT found!"<<std::endl;
	return false;
}

bool KillByGld(std::multimap<float, DWORD> &CAN, bool Simple, bool Strict, bool Aim) {
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	char* descA[]={"Glide", "3Dfx Interactive", NULL, NULL};
	char* itemA[]={"FileDescription", NULL, NULL};
	
	char* descB[]={"OpenGL", NULL, "MiniGL", NULL, "Direct3D", NULL, NULL,	"http://www.mesa3d.org", NULL, NULL};
	char* itemB[]={"FileDescription", NULL,									"Contact", NULL, NULL};
	
	char* wcrdA[]={"glide*.dll", NULL};
	
	char* wcrdB[]={"opengl*.dll", "3dfx*gl*.dll", "d3d*.dll", NULL};
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if ((Simple?CheckName((*rit).second, wcrdA):CheckDescription((*rit).second, descA, itemA))&&
			!(Strict?(Simple?CheckName((*rit).second, wcrdB):CheckDescription((*rit).second, descB, itemB)):false)) {
			std::cout<<"Process that uses Glide FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}
	
	std::cout<<"Process that uses Glide NOT found!"<<std::endl;
	return false;
}

bool KillByFsc(std::multimap<float, DWORD> &CAN, bool Strict, bool Apps, bool Aim) {
	std::multiset<DWORD> WND_PID;
	ENUM_CELL_FSC EnumCell;
	DEVMODE dmCurrent, dmRegistry;
	dmCurrent.dmSize=sizeof(DEVMODE);
	dmCurrent.dmDriverExtra=0;
	dmRegistry.dmSize=sizeof(DEVMODE);
	dmRegistry.dmDriverExtra=0;
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	if (EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &dmCurrent)&&
		EnumDisplaySettings(NULL, ENUM_REGISTRY_SETTINGS, &dmRegistry)) {
		
		EnumCell.dispW=dmCurrent.dmPelsWidth;
		EnumCell.dispH=dmCurrent.dmPelsHeight;
		EnumCell.taskbar_topmost=false;	
		EnumCell.pWndPid=&WND_PID;
		EnumWindows(Apps?(WNDENUMPROC)EnumFullscreenApps:(WNDENUMPROC)EnumFullscreenAll, (LPARAM)&EnumCell);
		
		if ((dmCurrent.dmPelsWidth==dmRegistry.dmPelsWidth)&&
			(dmCurrent.dmPelsHeight==dmRegistry.dmPelsHeight)&&
			EnumCell.taskbar_topmost&&Strict) {
			//Indirect signs of CDS_FULLSCREEN flag set:
			//	Current resolution != registry set resolution
			//	Start bar is not visible (well, actually, WS_VISIBLE is always set - the only difference is WS_EX_TOPMOST flag)
			std::cout<<"Process running in fullscreen NOT found!"<<std::endl;
			return false;
		}
		
		if (WND_PID.empty()) {
			std::cout<<"Process running in fullscreen NOT found!"<<std::endl;
			return false;
		}
		
		/****TEST***
		std::multiset<DWORD>::iterator it;
		for (it=WND_PID.begin(); it!= WND_PID.end(); it++)
			printf("%d\n", *it);
		****TEST***/
		
		for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
			if (WND_PID.find((*rit).second)!=WND_PID.end()) {
				std::cout<<"Process running in fullscreen FOUND!"<<std::endl;
				KillPid=(*rit).second;
				KillProcess(KillPid, Aim);
				CAN.erase(rit);
				return true;
			}
		}
	}
	
	std::cout<<"Process running in fullscreen NOT found!"<<std::endl;
	return false;
}

bool KillByPth(std::multimap<float, DWORD> &CAN, bool Full, bool Aim, char* Wcard) {
	DWORD KillPid;
	std::multimap<float, DWORD>::reverse_iterator rit;
	
	if (!Wcard) {
		Wcard="";
	}
	
	for (rit=CAN.rbegin(); rit!=CAN.rend(); rit++) {
		if (CheckPath((*rit).second, Full, Wcard)) {
			std::cout<<"Process that matches wildcard \""<<Wcard<<"\" FOUND!"<<std::endl;
			KillPid=(*rit).second;
			KillProcess(KillPid, Aim);
			CAN.erase(rit);
			return true;
		}
	}
	
	std::cout<<"Process that matches wildcard \""<<Wcard<<"\" NOT found"<<std::endl;
	return false;
}

void ContinueCheck(int &DIndex, char** Desc) {
	while (Desc[DIndex]||Desc[DIndex+1]) DIndex++;
	DIndex+=2;
}

bool CycleCheck(int DIndex, char** Desc, char* Buffer) {
	bool Found;
	
	while (Desc[DIndex]) {
		Found=true;
		
		while (Desc[DIndex]) {
			if (!strstr(Buffer, Desc[DIndex])) {
				Found=false;
			}
			DIndex++;
		}
		
		if (Found) break;
		DIndex++;
	}
	
	return Found;
}

bool CheckDescription(DWORD PID, char** Desc, char** Item) {
	HMODULE *aModules=NULL;
	DWORD cbNeeded, cModules, cbAllocated=0;
	HANDLE hProcess;
	BYTE *pBlock=NULL;
	bool Found=false;
	char QueryBlock[64];
	
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
		DWORD zero=0;
		DWORD dwLen=0;
		struct LANGANDCODEPAGE *lpTranslate;
		UINT cbTranslate, dwBytes;
		char SubBlock[64];
		char* lpBuffer;
		
		if (pBlock) delete[] pBlock;
		pBlock=NULL;

		if (GetModuleFileNameEx(hProcess, aModules[i], szModName, sizeof(szModName))) {
			//printf("\t%s (0x%08X)\n", szModName, aModules[i] );
			
			if(!(dwLen=GetFileVersionInfoSize(szModName, &zero))) continue;

			pBlock=new BYTE[dwLen];

			if(!GetFileVersionInfo(szModName, 0, dwLen, (LPVOID)pBlock)) continue;

			VerQueryValue((LPVOID)pBlock, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate);
			
			int ii=0, di=0;
			bool trFound;
			while (Item[ii]) {
				Found=true;
	
				while (Item[ii]) {
					if (ii) ContinueCheck(di, Desc);
					strcpy(QueryBlock, "\\StringFileInfo\\%04x%04x\\");
					strcat(QueryBlock, Item[ii]);
					
					trFound=false;
					for(unsigned int x=0; x<(cbTranslate/sizeof(struct LANGANDCODEPAGE)); x++) {
						sprintf(SubBlock, QueryBlock, lpTranslate[x].wLanguage, lpTranslate[x].wCodePage);
						if (!VerQueryValue((LPVOID)pBlock, SubBlock, (LPVOID*)&lpBuffer, &dwBytes)) continue;
						//printf("\t\t%s\n", lpBuffer);
						if (trFound=CycleCheck(di, Desc, lpBuffer)) break;
					}
					if (!trFound) Found=false;
					
					ii++;
				}
				
				if (Found) break;
				ii++;
			}
		}
		
		if (Found) break;
	}
	
	if (pBlock) delete[] pBlock;
	delete[] aModules;	
	CloseHandle(hProcess);
	
	return Found;
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

BOOL CALLBACK EnumFullscreenApps(HWND WinHandle, LPARAM Param)
{
	ENUM_CELL_FSC *pEnumCell;
	RECT rect;
	char buf_cls[256];
	DWORD PID=0;
	LONG_PTR StRes, ExStRes;
	
	pEnumCell=(ENUM_CELL_FSC*)Param;
	
	StRes=GetWindowLongPtr(WinHandle, GWL_STYLE);
	
	if (!StRes) return true;
	
	ExStRes=GetWindowLongPtr(WinHandle, GWL_EXSTYLE);
	
	//Standart techique to run fullscreen is to set app's windows to WS_POPUP.
	//But in Vista (and up, thanks to DWM) it's not a good idea to use WS_POPUP in fullscreen apps.
	//Workaround fow Vista is to use WS_CAPTION (with WS_OVERLAPPED) without rest of WS_OVERLAPPEDWINDOW
	//and then properly handle paint events to hide caption bar and window box.
	//So there is one common thing between this two window styles:
	//there is no need to use window resizing - WS_SIZEBOX is unnecessary
	//Also, some apps (non-3d-game-apps) are using just WS_OVERLAPPED 
	//(without even WS_CAPTION) to go fullscreen ("dirty" technique)
	//Some system top level windows use WS_CHILDWINDOW.
	//Most system windows are WS_EX_TOOLWINDOW and not WS_VISIBLE.
	
	if (ExStRes) {
		if ((StRes&WS_VISIBLE)&&!(StRes&WS_CHILDWINDOW)&&!(StRes&WS_SIZEBOX)&&!(ExStRes&WS_EX_TOOLWINDOW)) {
			if (GetClientRect(WinHandle, &rect)) {
				if ((pEnumCell->dispW<=rect.right-rect.left)&&(pEnumCell->dispH<=rect.bottom-rect.top)) {	//Sometimes fullscreen windows can be even larger than actual display resolution
					GetWindowThreadProcessId(WinHandle, &PID);
					pEnumCell->pWndPid->insert(PID);
					//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
				}
			} else {
				GetWindowThreadProcessId(WinHandle, &PID);
				pEnumCell->pWndPid->insert(PID);
				//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
			}
		}
		
		if (GetClassName(WinHandle, buf_cls, sizeof(buf_cls))) {
			if (!strcmp(buf_cls, "Shell_TrayWnd")) {
				pEnumCell->taskbar_topmost=ExStRes&WS_EX_TOPMOST;
			}
		}
	} else {
		if ((StRes&WS_VISIBLE)&&!(StRes&WS_CHILDWINDOW)&&!(StRes&WS_SIZEBOX)) {
			if (GetClientRect(WinHandle, &rect)) {
				if ((pEnumCell->dispW<=rect.right-rect.left)&&(pEnumCell->dispH<=rect.bottom-rect.top)) {	//Sometimes fullscreen windows can be even larger than actual display resolution
					GetWindowThreadProcessId(WinHandle, &PID);
					pEnumCell->pWndPid->insert(PID);
					//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
				}
			} else {
				GetWindowThreadProcessId(WinHandle, &PID);
				pEnumCell->pWndPid->insert(PID);
				//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
			}
		}
	}
	
	return true;
}

BOOL CALLBACK EnumFullscreenAll(HWND WinHandle, LPARAM Param)
{
	ENUM_CELL_FSC *pEnumCell;
	RECT rect;
	char buf_cls[256];
	DWORD PID=0;
	LONG_PTR ExStRes;
	
	pEnumCell=(ENUM_CELL_FSC*)Param;
	
	ExStRes=GetWindowLongPtr(WinHandle, GWL_EXSTYLE);
	
	if (GetWindowRect(WinHandle, &rect)) {
		if ((pEnumCell->dispW==rect.right-rect.left)&&(pEnumCell->dispH==rect.bottom-rect.top)) {
			GetWindowThreadProcessId(WinHandle, &PID);
			pEnumCell->pWndPid->insert(PID);
			//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
		}
	} else {
		GetWindowThreadProcessId(WinHandle, &PID);
		pEnumCell->pWndPid->insert(PID);
		//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
	}
	
	if (GetClassName(WinHandle, buf_cls, sizeof(buf_cls))) {
		if (!strcmp(buf_cls, "Shell_TrayWnd")) {
			pEnumCell->taskbar_topmost=ExStRes&WS_EX_TOPMOST;
		}
	}

	return true;
}

BOOL CALLBACK EnumNotResponding(HWND WinHandle, LPARAM Param)
{
	ENUM_CELL_INR *pEnumCell;
	DWORD PID=0;
	LONG_PTR StRes;
	char class_name[6]="";

	pEnumCell=(ENUM_CELL_INR*)Param;
	
	StRes=GetWindowLongPtr(WinHandle, GWL_STYLE);
	
	if (!StRes) return true;
	
	if (GetClassName(WinHandle, class_name, 6)) {
		if (StRes&WS_VISIBLE) {	//Checks only visible windows - some hidden technical windows can be accidentially detected as hung.
			switch (pEnumCell->mode) {
				case 'H':
					if (strcmp(class_name, "Ghost")) {
						if (IsHungAppWindow(WinHandle)==1) {	//Needs _WIN32_WINNT=0x0502.
							GetWindowThreadProcessId(WinHandle, &PID);
							pEnumCell->pWndPid->insert(PID);
							//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
						}
					}
					break;
				case 'M':
					if (strcmp(class_name, "Ghost")) {
						if (SendMessageTimeout(WinHandle, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, INR_TIMEOUT, NULL)==0) {
							GetWindowThreadProcessId(WinHandle, &PID);
							pEnumCell->pWndPid->insert(PID);
							//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
						}
					}
					break;
				case 'G':
					if (!strcmp(class_name, "Ghost")) {
						if (WinHandle=extraUserHungWindowFromGhostWindow(WinHandle)) {	//Undocumented function, Vista or higher required.
							GetWindowThreadProcessId(WinHandle, &PID);
							pEnumCell->pWndPid->insert(PID);
							//printf("window handle 0x%08X with pid %d\n", WinHandle, PID);
						}
					}
					break;
			}
		}
	}
	
	return true;
}
