#include "Killers.h"
#include "FilePathRoutines.h"
#include "Extras.h"
#include "Common.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <tuple>
#include <vector>
#include <algorithm>
#include <cstdio>

#define INR_TIMEOUT					5000 //ms

typedef struct _LANGANDCODEPAGE {
	WORD wLanguage;
	WORD wCodePage;
} LANGANDCODEPAGE;

extern pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow;

#ifdef _WIN64
#define EnumDisplayDevicesWrapper EnumDisplayDevices
#else
extern "C" BOOL __cdecl EnumDisplayDevicesWrapper(LPCTSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICE lpDisplayDevice, DWORD dwFlags, BOOL (WINAPI *fnPtr)(LPCWSTR, DWORD, PDISPLAY_DEVICEW, DWORD)=EnumDisplayDevices, DWORD dwEBP=0);
#endif

#ifdef __clang__
//Obscure clang++ bug - it reports "multiple definition" of std::setfill() when statically linking with libstdc++
//Observed on LLVM 3.6.2 with MinGW 4.7.2
//This is a fix for the bug
extern template std::_Setfill<wchar_t> std::setfill(wchar_t);	//caused by use of std::setfill(wchar_t)
#endif

Killers::Killers()
{}

void Killers::KillProcess(DWORD PID, const std::wstring &name) 
{
	if (ModeBlank()) {
		std::wcout<<L"Troublemaker process: "<<PID<<L" ("<<name<<L")!"<<std::endl;
	} else {
		//PROCESS_TERMINATE is needed for TerminateProcess
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_TERMINATE);
									
		if (!hProcess) {
			std::wcout<<L"Troublemaker process: "<<PID<<L" ("<<name<<L") - process can't be terminated!"<<std::endl;
			return;
		}
		
		TerminateProcess(hProcess, 1);
		std::wcout<<L"Process "<<PID<<L" ("<<name<<L") killed!"<<std::endl;
		CloseHandle(hProcess);
	}
}

bool Killers::KillByCpu() 
{
	bool found=ApplyToProcesses([this](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		std::wcout<<L"Process with highest cpu usage FOUND!"<<std::endl;
		KillProcess(PID, name);
		return true;
	});
	
	if (found) {
		return true;
	} else {
		std::wcout<<L"Process with highest cpu usage NOT found!"<<std::endl;
		return false;
	}
}

bool Killers::KillByPth(bool param_full, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		if (MultiWildcardCmp(arg_wcard, param_full?path.c_str():name.c_str())) {
			std::wcout<<L"Process that matches wildcard(s) \""<<arg_wcard<<L"\" FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that matches wildcard(s) \""<<arg_wcard<<L"\" NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByMod(bool param_full, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByMod:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif

		if (CheckName(mlist, param_full, arg_wcard)) {
			std::wcout<<L"Process with module that matches wildcard(s) \""<<arg_wcard<<L"\" FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process with module that matches wildcard(s) \""<<arg_wcard<<L"\" NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByPid(const wchar_t* arg_parray) 
{
	std::vector<ULONG_PTR> uptr_array;
	
	if (!arg_parray||!PidListCmp(arg_parray, uptr_array))
		arg_parray=L"";
	
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KillByPid:"<<__LINE__<<L": Dumping generated PID list for \""<<arg_parray<<L"\"..."<<std::endl;
	for (ULONG_PTR &uptr_i: uptr_array)
		std::wcerr<<L"\t\t"<<uptr_i<<std::endl;
#endif
	
	bool found=!uptr_array.empty()&&ApplyToProcesses([this, arg_parray, &uptr_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		if (PidListCmp(uptr_array, PID)) {
			std::wcout<<L"Process that matches PID(s) \""<<arg_parray<<L"\" FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that matches PID(s) \""<<arg_parray<<L"\" NOT found"<<std::endl;
		return false;
	}
}

//Checks if StringFileInfo ITEM contains DESC string
//Check is case-sensetive for both DESCs and ITEMs
//If you want to check if ITEM simply exists - pass empty DESC
//const wchar_t* desc_str[]={"I1_str1 OR", NULL, "(I1_str2A AND", "I1_str2B)", NULL, NULL,		"I2A_str1", NULL, NULL, 	"I2B_str1", NULL, NULL};
//const wchar_t* item_str[]={"Item1 OR", NULL,													"(Item2A AND",				"Item2B)", NULL, NULL};
bool Killers::CheckStringFileInfo(const wchar_t* fpath, const wchar_t** item_str, const wchar_t** desc_str) 
{
	enum MatchState:char {IN_PROGRESS, CLAUSE_FAILED, ARRAY_MATCHED};
	MatchState item_matched=IN_PROGRESS;	
	MatchState desc_matched=IN_PROGRESS;

	if (DWORD buflen=GetFileVersionInfoSize(fpath, NULL)) {					//Proceed only if FPATH could be queried
		BYTE retbuf[buflen];
		if (GetFileVersionInfo(fpath, 0, buflen, (LPVOID)retbuf)) {
			LANGANDCODEPAGE *plcp;
			UINT lcplen;
			if (VerQueryValue((LPVOID)retbuf, L"\\VarFileInfo\\Translation", (LPVOID*)&plcp, &lcplen)) {
				for (; lcplen; plcp++, lcplen-=sizeof(LANGANDCODEPAGE)) {	//Traversing translations this early because most of the DLLs actually have only one translation
					for (; item_str[0]||item_str[1]; item_str++) {						//Loop ITEM until NULL NULL
						if (!item_str[0]) { item_matched=IN_PROGRESS; continue; }		//If OR - reset ITEM match and continue
						if (item_matched==CLAUSE_FAILED) continue;						//If current clause failed - continue until OR or NULL NULL
						
						wchar_t *value;
						UINT valuelen;
						std::wstringstream qstr;
						qstr<<std::nouppercase<<std::noshowbase<<std::hex<<L"\\StringFileInfo\\"<<std::setfill(L'0')<<std::setw(4)<<plcp->wLanguage<<std::setfill(L'0')<<std::setw(4)<<plcp->wCodePage<<L"\\"<<item_str[0];
						if (VerQueryValue((LPVOID)retbuf, qstr.str().c_str(), (LPVOID*)&value, &valuelen)) {
#if DEBUG>=3
							std::wcerr<<L"" __FILE__ ":CheckStringFileInfo:"<<__LINE__<<L": "<<fpath<<L":"<<qstr.str()<<L"=\""<<value<<L"\" matching..."<<std::endl;
#endif
							desc_matched=IN_PROGRESS;
							for (; desc_str[0]||desc_str[1]; desc_str++) {							//Loop DESC until NULL NULL
								if (desc_matched==ARRAY_MATCHED) continue;							//If DESC array was already matched - continue until NULL NULL
								if (!desc_str[0]) { desc_matched=IN_PROGRESS; continue; }			//If OR - reset DESC match and continue
								if (desc_matched==CLAUSE_FAILED) continue;							//If current clause failed - continue until OR or NULL NULL
								
								if (wcsstr(value, desc_str[0])) {									//Poses as "*DESC*" wildcard, case-sensetive, and also matches empty DESCs
									if (!desc_str[1]) desc_matched=ARRAY_MATCHED;					//If DESC matched and next DESC will be OR (or NULL NULL) - mark this DESC array as matched
										else desc_matched=IN_PROGRESS;								//If DESC matched and next DESC will be ANDed - continue matching process
								} else
									desc_matched=CLAUSE_FAILED;										//If DESC not matched - mark this clause as failed
#if DEBUG>=3
								std::wcerr<<L"\t\t"<<desc_str[0]<<(desc_matched==CLAUSE_FAILED?L" [FAILED]":desc_matched==ARRAY_MATCHED?L" [PASSED]":L" [NEXT]")<<std::endl;
#endif
							}
							desc_str+=2;													//Set DESC array to the next set of DESCs to match

							if (desc_matched==ARRAY_MATCHED) {
								if (!item_str[1]) { item_matched=ARRAY_MATCHED;	break; }	//If DESC array for this ITEM matched and next ITEM will be OR (or NULL NULL) - mark ITEM array as matched and stop matching process
									else item_matched=IN_PROGRESS;							//If DESC array for this ITEM matched and next ITEM will be ANDed - continue matching process 
							} else
								item_matched=CLAUSE_FAILED;									//If DESC not matched - mark this clause as failed							
						} else {
#if DEBUG>=3
							std::wcerr<<L"" __FILE__ ":CheckStringFileInfo:"<<__LINE__<<L": "<<fpath<<L":"<<qstr.str()<<L" not found!"<<std::endl;
#endif
							for (; desc_str[0]||desc_str[1]; desc_str++);					//ITEM wasn't found in StringFileInfo structure
							desc_str+=2;													//So loop DESC array to the next one
							item_matched=CLAUSE_FAILED;										//And mark this clause as failed
						}
					}
				}
			}
		}
	}
	
	return item_matched==ARRAY_MATCHED;
}

bool Killers::CheckName(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, bool full, const wchar_t* wcard) 
{
	for (const std::pair<std::wstring, std::wstring> &module: mlist)
		if (MultiWildcardCmp(wcard, full?module.second.c_str():module.first.c_str())) return true;
	
	return false;
}

bool Killers::CheckDescription(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, const wchar_t** item_str, const wchar_t** desc_str) 
{
	for (const std::pair<std::wstring, std::wstring> &module: mlist)
		if (CheckStringFileInfo(module.second.c_str(), item_str, desc_str)) return true;
	
	return false;
}

bool Killers::KillByD3d(bool param_simple) 
{
	//"DirectX Driver" - rare case used in description of
	//3Dfx (and it's vendors) driver bundle
	const wchar_t* descA[]={L"Direct3D", NULL, L"DirectX Driver", NULL, NULL};
	const wchar_t* itemA[]={L"FileDescription", NULL, NULL};
	
	const wchar_t* wcrdA=L"d3d*.dll";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByD3d:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckName(mlist, false, wcrdA):CheckDescription(mlist, itemA, descA)) {
			std::wcout<<L"Process that uses Direct3D FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that uses Direct3D NOT found!"<<std::endl;
		return false;
	}
}

bool Killers::KillByOgl(bool param_simple) 
{
	const wchar_t* descA[]={L"OpenGL", NULL, L"MiniGL", NULL, NULL,	L"http://www.mesa3d.org", NULL, NULL};
	const wchar_t* itemA[]={L"FileDescription", NULL,				L"Contact", NULL, NULL};
	
	const wchar_t* wcrdA=L"opengl*.dll;3dfx*gl*.dll";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByOgl:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckName(mlist, false, wcrdA):CheckDescription(mlist, itemA, descA)) {
			std::wcout<<L"Process that uses OpenGL FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that uses OpenGL NOT found!"<<std::endl;
		return false;
	}
}

bool Killers::KillByGld(bool param_simple) 
{
	const wchar_t* descA[]={L"Glide", L"3Dfx Interactive", NULL, NULL};
	const wchar_t* itemA[]={L"FileDescription", NULL, NULL};
	
	const wchar_t* wcrdA=L"glide*.dll";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByGld:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckName(mlist, false, wcrdA):CheckDescription(mlist, itemA, descA)) {
			std::wcout<<L"Process that uses Glide FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that uses Glide NOT found!"<<std::endl;
		return false;
	}
}

//Checks if window is task-window - window that is eligible to be shown in Task Bar and Task Switcher (Alt+Tab)
bool Killers::IsTaskWindow(HWND hwnd)
{
	LONG_PTR lpStyleEx=GetWindowLongPtr(hwnd, GWL_EXSTYLE);
	
	return ((lpStyleEx&WS_EX_APPWINDOW)||!(lpStyleEx&WS_EX_TOOLWINDOW))&&IsWindowVisible(hwnd)&&IsWindowEnabled(hwnd);
}

//Checks if inner RECT is within outer RECT (it's assumed that RECTs are valid)
bool Killers::WithinRect(const RECT &outer, const RECT &inner)
{
	return inner.left>=outer.left&&inner.top>=outer.top&&inner.right<=outer.right&&inner.bottom<=outer.bottom;
}

bool Killers::KillByInr(InrMode param_mode) 
{
	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId return PID as DWORD

#if DEBUG>=2
	if (!fnNtUserHungWindowFromGhostWindow) {
		std::wcerr<<L"" __FILE__ ":KillByInr:"<<__LINE__<<L": NtUserHungWindowFromGhostWindow not found!"<<std::endl;
	}
#endif

	//Unfortunately, can't use those pretty capture-less lambdas here because of calling conventions
	//By default lambda calling conventions is __cdecl, which is OK on x86-64 because CALLBACK is also __cdecl here
	//But on good old x86 CALLBACK is __stdcall which is incompatible with __cdecl
	//At least we can use tuples so not to litter class definition with structs
	WNDCLASS dummy_wnd;
	std::tuple<InrMode, std::vector<DWORD>&, ATOM> enum_wnd_tuple(param_mode, dw_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
	//The trick with GetClassInfo is described by Raymond Chen in his blog http://blogs.msdn.com/b/oldnewthing/archive/2004/10/11/240744.aspx
	//Undocumented side of GetClassInfo is that it returns ATOM for the queried window class
	//By passing NULL as HINSTANCE we can get ATOM for the system "Ghost" class
	EnumWindows(EnumWndInr, (LPARAM)&enum_wnd_tuple);
	
	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			std::wcout<<L"Process that is not responding FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process that is not responding NOT found"<<std::endl;
		return false;
	}
}

BOOL CALLBACK Killers::EnumWndInr(HWND hwnd, LPARAM lParam) 
{
	InrMode mode=std::get<0>(*(std::tuple<InrMode, std::vector<DWORD>&, ATOM>*)lParam);
	std::vector<DWORD> &dw_array=std::get<1>(*(std::tuple<InrMode, std::vector<DWORD>&, ATOM>*)lParam);
	ATOM ghost_atom=std::get<2>(*(std::tuple<InrMode, std::vector<DWORD>&, ATOM>*)lParam);
					
	if (IsTaskWindow(hwnd)) {
		DWORD pid;
		switch (mode) {
			case DEFAULT:	
				//This is the way Windows checks if application is hung - using IsHungAppWindow
				//Mechanism behind IsHungAppWindow considers window hung if it's thread:
				//	isn't waiting for input
				//	isn't in startup processing
				//	hasn't called PeekMessage() within some time interval (5 sec for IsHungAppWindow)
				//The trick is that IsHungAppWindow will return true for both app's own window and it's "ghost" window (that belongs to dwm or explorer)
				//IsHungAppWindow fails to detect apps that were specifically made to be hung (using SuspendThread)
				//But outside test environment it's almost impossible case
				if (IsHungAppWindow(hwnd))
					//Check that hung window is not "ghost" window
					//Comparing class name with "Ghost" can be unreliable - application can register it's own local class with that name
					//But outside of enum function we already got ATOM of the actual system "Ghost" class
					//So all we have to do is just compare window class ATOM with "Ghost" class ATOM
					if (GetClassLongPtr(hwnd, GCW_ATOM)!=ghost_atom)
						if (GetWindowThreadProcessId(hwnd, &pid))
							dw_array.push_back(pid);
				break;					
			case MANUAL:
				//Pretty straightforward method that is suggested by MS https://support.microsoft.com/kb/231844
				//Just wait for SendMessageTimeout to fail - because of abort (if app is hung) or actual timeout
				//This method perfectly detects SuspendThread test apps 
				//It doesn't trigger on "ghost" windows
				//But ironically fails to detect some normal hung apps that trigger IsHungAppWindow
				//That's because internally SMTO_ABORTIFHUNG uses the same mechanism of checking hung windows as IsHungAppWindow but with different time constants
				//While IsHungAppWindow checks if PeekMessage() hasn't been called within 5 sec interval, for SMTO_ABORTIFHUNG this interval is 20 sec
				if (!SendMessageTimeout(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG|SMTO_BLOCK, INR_TIMEOUT, NULL))
					if (GetWindowThreadProcessId(hwnd, &pid))
						dw_array.push_back(pid);
				break;
			case VISTA:
				//Undocumented function that is available starting from Vista
				//In contrast with IsHungAppWindow it triggers only on "ghost" windows
				//And returns HWND of the actual hung window
				//So in the end it is more convenient than IsHungAppWindow
				if (fnNtUserHungWindowFromGhostWindow&&(hwnd=fnNtUserHungWindowFromGhostWindow(hwnd)))
					if (GetWindowThreadProcessId(hwnd, &pid))
						dw_array.push_back(pid);
				break;
		}
	}
	
	return true;
}

bool Killers::KillByFsc(bool param_anywnd, bool param_primary) 
{
	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId return PID as DWORD
	std::vector<RECT> disp_array;
	
	//So what's the deal with EnumDisplayDevicesWrapper and intersecting switch/while?
	//EnumDisplayDevices takes 4 parameters and iDevNum starts at 0
	//But not on NT4 - here it will take 3 parameters and iDevNum starts at 1
	//Detecting OS version, importing EnumDisplayDevices with proper prototype and dealing with these cases separately - no fun
	//Intersecting switch/while will check both iDevNum start positions
	//And wrapper will deal with variable number of parameters
	//Because calling STDCALL function which takes less params than expected will in most cases lead to stack corruption
	//Wrapping STDCALL in plain CDECL function that just passes parameters at first seemed a good idea
	//But tests showed that it's not guaranteed that proper stack frame (push ebp; mov ebp,esp; ... leave;) will be used by compiler
	//E.g. Clang (-march=pentium2) restores ESP with "add esp,X" which doesn't prevent stack corruption
	//So custom assembler wrapper is used that not only restores stack but also omits unnecessary parameter relocations
	//And on x86-64 this wrapper is just a synonym for ordinary EnumDisplayDevices - no special moves here
	DISPLAY_DEVICE ddDev={sizeof(DISPLAY_DEVICE)};
	DWORD iDevNum=0;
	switch (EnumDisplayDevicesWrapper(NULL, 0, &ddDev, 0)) {
		case 0:
			while (EnumDisplayDevicesWrapper(NULL, ++iDevNum, &ddDev, 0)) {
		default:
				DEVMODE dmDev;
				dmDev.dmSize=sizeof(DEVMODE);
				dmDev.dmDriverExtra=0;
				//Instead of checking DISPLAY_DEVICE_ATTACHED_TO_DESKTOP flag test if display currently setup (i.e. actually being used)
				if (EnumDisplaySettings(ddDev.DeviceName, ENUM_CURRENT_SETTINGS, &dmDev)) {
					//Move primary display to the first position in array
					if (ddDev.StateFlags&DISPLAY_DEVICE_PRIMARY_DEVICE)
						disp_array.insert(disp_array.begin(), {dmDev.dmPosition.x, dmDev.dmPosition.y, dmDev.dmPosition.x+(LONG)dmDev.dmPelsWidth, dmDev.dmPosition.y+(LONG)dmDev.dmPelsHeight});
					else
						disp_array.push_back({dmDev.dmPosition.x, dmDev.dmPosition.y, dmDev.dmPosition.x+(LONG)dmDev.dmPelsWidth, dmDev.dmPosition.y+(LONG)dmDev.dmPelsHeight});
				}
			}	
	}
	
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KillByFsc:"<<__LINE__<<L": Dumping displays..."<<std::endl;
	for (const RECT &disp: disp_array)
		std::wcerr<<L"\t\t("<<disp.left<<L","<<disp.top<<L")("<<disp.right<<L","<<disp.bottom<<L")"<<std::endl;
#endif

	//Unfortunately, can't use those pretty capture-less lambdas here because of calling conventions
	//By default lambda calling conventions is __cdecl, which is OK on x86-64 because CALLBACK is also __cdecl here
	//But on good old x86 CALLBACK is __stdcall which is incompatible with __cdecl
	//At least we can use tuples so not to litter class definition with structs
	if (!disp_array.empty()) {
		std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&> enum_wnd_tuple(param_anywnd, param_primary, dw_array, disp_array);
		EnumWindows(EnumWndFsc, (LPARAM)&enum_wnd_tuple);
	}
	
	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			std::wcout<<L"Process running in fullscreen FOUND!"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"Process running in fullscreen NOT found"<<std::endl;
		return false;
	}
}

//Don't make tons of empty vector checks - this callback is called for a lot of windows
//Just don't call EnumWindows at first place if display vector is empty
//This will also guarantee that display vector is non-empty in this callback
BOOL CALLBACK Killers::EnumWndFsc(HWND hwnd, LPARAM lParam) 
{
	bool any_wnd=std::get<0>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&>*)lParam);
	bool pri_disp=std::get<1>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&>*)lParam);
	std::vector<DWORD> &dw_array=std::get<2>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&>*)lParam);
	std::vector<RECT> &disp_array=std::get<3>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&>*)lParam);
	
	if (IsTaskWindow(hwnd)) {
		RECT client_rect;
		RECT window_rect;
		if (GetClientRect(hwnd, &client_rect)&&GetWindowRect(hwnd, &window_rect)) {
			//If any_wnd - assuming that we are testing apps with any type of window
			//	If game is forced to run in window it's client RECT not necessary equals set resolution (often it's smaller)
			//	But it's window RECT always greater than set resolution and display RECT will be within window RECT
			//Otherwise - assuming that we are testing exclusive fullscreen apps or apps that have borderless window
			//	Check if client area dimension equals window dimension - should be true for both exclusive fullscreen and borderless window
			//	Client RECT's top left corner is always at (0,0) so bottom right corner represents width/height of client area
			if (any_wnd||(client_rect.right==window_rect.right-window_rect.left&&client_rect.bottom==window_rect.bottom-window_rect.top)) {
#if DEBUG>=3
				std::wcerr<<L"" __FILE__ ":EnumWndFsc:"<<__LINE__<<L": HWND ("<<std::hex<<(ULONG_PTR)hwnd<<std::dec<<L") - CRECT=("
					<<client_rect.left<<L","<<client_rect.top<<L")("<<client_rect.right<<L","<<client_rect.bottom<<L") - WRECT=("
					<<window_rect.left<<L","<<window_rect.top<<L")("<<window_rect.right<<L","<<window_rect.bottom<<L")"<<std::endl;
#endif
				DWORD pid;
				if (disp_array.size()==1) {
					//If we have only one display - use more relaxed algorithm
					//Some fullscreen game windows have their coordinates unaligned with display (e.g. Valkyria Chronicles)
					//Some fullscreen game windows have size greater than display size
					//So just check that app's window size is greater or equal to display size
					if (window_rect.right-window_rect.left>=disp_array[0].right-disp_array[0].left&&window_rect.bottom-window_rect.top>=disp_array[0].bottom-disp_array[0].top)
						if (GetWindowThreadProcessId(hwnd, &pid))
							dw_array.push_back(pid);
				} else {
					//Relaxed algorithm that is suitable for single display can cause false positive on multiple displays
					//For multiple displays test if app's RECT contains at least one of the displays' RECT to consider it fullscreen app
					//Still, games for which relaxed algorithm works best behave the same on multiple displays and therefore will not be considered fullscreen there
					//In this case KillByFgd is more suitable
					if (pri_disp
						?WithinRect(window_rect, disp_array[0])
						:std::any_of(disp_array.begin(), disp_array.end(), std::bind(WithinRect, window_rect, std::placeholders::_1)))
						if (GetWindowThreadProcessId(hwnd, &pid))
							dw_array.push_back(pid);
				}
			}
		}
	}

	return true;
}

bool Killers::KillByFgd()
{
	DWORD pid;
	HWND hwnd;

	bool found=(hwnd=GetForegroundWindow())&&IsTaskWindow(hwnd)&&GetWindowThreadProcessId(hwnd, &pid)&&
		ApplyToProcesses([this, pid](ULONG_PTR PID, const std::wstring &name, const std::wstring &path){
			if (pid==PID) {
				std::wcout<<L"Process with foreground window FOUND!"<<std::endl;
				KillProcess(PID, name);
				return true;
			} else
				return false;
		});

	if (found)
		return true;
	else {
		std::wcout<<L"Process with foreground window NOT found"<<std::endl;
		return false;
	}
}
