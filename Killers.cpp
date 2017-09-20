#include "Killers.h"
#include "FilePathRoutines.h"
#include "Extras.h"
#include "Common.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <tuple>
#include <algorithm>
#include <cstdio>

#define INR_TIMEOUT					5000 //ms

typedef struct _LANGANDCODEPAGE {
	WORD wLanguage;
	WORD wCodePage;
} LANGANDCODEPAGE;

extern pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow;
extern pNtQueryInformationProcess fnNtQueryInformationProcess;

#ifdef _WIN64
#define EnumDisplayDevicesWrapper EnumDisplayDevices
#else
extern "C" BOOL __stdcall EnumDisplayDevicesWrapper(LPCTSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICE lpDisplayDevice, DWORD dwFlags, DWORD=0, DWORD=0);
#endif

#ifdef __clang__
//Obscure clang++ bug - it reports "multiple definition" of std::setfill() when statically linking with libstdc++
//Observed on LLVM 3.6.2 with MinGW 4.7.2
//This is a fix for the bug
extern template std::_Setfill<wchar_t> std::setfill(wchar_t);	//caused by use of std::setfill(wchar_t)
#endif

Killers::Killers()
{}

void Killers::PrintCommonKillPrefix()
{
	if (ModeLoop()) {
		if (ModeAll())
			std::wcout<<L"Processes ";
		else
			std::wcout<<L"User processes ";	
	} else {
		if (ModeRecent()&&ModeAll())
			std::wcout<<L"Recently created process ";
		else if (ModeAll())
			std::wcout<<L"Process with highest CPU usage ";
		else if (ModeRecent())
			std::wcout<<L"Recently created user process ";
		else
			std::wcout<<L"User process with highest CPU usage ";
	}
}

void Killers::KillProcess(DWORD PID, const std::wstring &name) 
{
	if (ModeBlank()) {
		if (ModeBlacklist())
			std::wcout<<PID<<L" ("<<name<<L") - blacklisted"<<std::endl;
		else if (ModeWhitelist())
			std::wcout<<PID<<L" ("<<name<<L") - whitelisted"<<std::endl;
		else
			std::wcout<<PID<<L" ("<<name<<L")"<<std::endl;
	} else {
		if (!ModeClose()||EnumWindows(EnumWndClose, (LPARAM)PID)||GetLastError()) {
			HANDLE hProcess;
			//PROCESS_TERMINATE is needed for TerminateProcess
			if ((hProcess=OpenProcessWrapper(PID, PROCESS_TERMINATE))&&TerminateProcess(hProcess, 1))
				std::wcout<<PID<<L" ("<<name<<L") - killed"<<std::endl;
			else
				std::wcout<<PID<<L" ("<<name<<L") - can't be terminated"<<std::endl;
			if (hProcess) CloseHandle(hProcess);
		} else
			std::wcout<<PID<<L" ("<<name<<L") - closed"<<std::endl;
	}
}

BOOL CALLBACK Killers::EnumWndClose(HWND hwnd, LPARAM lParam) 
{
	DWORD pid;
	if (GetWindowThreadProcessId(hwnd, &pid)&&pid==(DWORD)lParam) {
		//Returning FALSE not only causes EnumWindows to stop enumeration, but also causes it to return FALSE (i.e. error value)
		//To distinguish between real error and succesfull premature end of enumeration, it's better set some last-error code with SetLastError
		//SendMessageTimeout not necessary sets non-zero last-error code if fails, so we forcing it here
		//If function doesn't fail, last-error code is zero
		if (!SendMessageTimeout(hwnd, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG|SMTO_BLOCK, INR_TIMEOUT, NULL))
			SetLastError(ERROR_TIMEOUT);
		return FALSE;
	} else
		return TRUE;
}

bool Killers::KillByCpu() 
{
	PrintCommonKillPrefix();
	bool found=ApplyToProcesses([this](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (!applied) std::wcout<<L"FOUND:"<<std::endl;
		KillProcess(PID, name);
		return true;
	});
	
	if (found) {
		return true;
	} else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByPth(bool param_full, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that match wildcard(s) \"";
	else
		std::wcout<<L"that matches wildcard(s) \"";
	std::wcout<<arg_wcard;
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (MultiWildcardCmp(arg_wcard, param_full?path.c_str():name.c_str(), param_full)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"\" NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByMod(bool param_full, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	PrintCommonKillPrefix();
	std::wcout<<L"having modules that match wildcard(s) \""<<arg_wcard;
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByMod:"<<__LINE__<<L": Processing modules for \""<<name<<L"\"..."<<std::endl;
#endif
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByMod:"<<__LINE__<<L": Dumping modules for \""<<name<<L"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif

		if (CheckModListNames(mlist, param_full, arg_wcard)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"\" NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByPid(bool param_parent, const wchar_t* arg_parray) 
{
	if (param_parent)
		return KillParentPid();
	else
		return KillPidsInArray(arg_parray);
}

bool Killers::KillParentPid() 
{
	ULONG_PTR parent_pid=0;	//0 is idle process PID and which can't be parent of any process

	if (fnNtQueryInformationProcess) {
		PROCESS_BASIC_INFORMATION proc_info;
		if (NT_SUCCESS(fnNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &proc_info, sizeof(PROCESS_BASIC_INFORMATION), NULL))) {
			parent_pid=proc_info.InheritedFromUniqueProcessId;
		} else {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":KillParentPid:"<<__LINE__<<L": NtQueryInformationProcess(ProcessBasicInformation) failed!"<<std::endl;
#endif
		}
	} else {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":KillParentPid:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
	}
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that match parent PID ";
	else
		std::wcout<<L"that matches parent PID ";
	
	bool found=parent_pid&&ApplyToProcesses([this, parent_pid](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (PID==parent_pid) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::PidListPrepare(const wchar_t* pid_list, std::vector<ULONG_PTR> &uptr_array) 
{
	if (!pid_list)
		return false;
	
	ULONG_PTR dw_pri, dw_sec, *pdw_cur=&dw_pri;
	wchar_t* rtok;
	bool cnv_err=false;
	
	wchar_t buffer[wcslen(pid_list)+1];
	wcscpy(buffer, pid_list);
	
	for (wchar_t* token=wcstok(buffer, L",;"); token; token=wcstok(NULL, L",;")) {
		for(;;) {
			if (!*token||*token==L'-'||*token==L'+'||*token==L' ') {
				cnv_err=true;
				break;
			}
			*pdw_cur=wcstoul(token, &rtok, 0);
			if ((*pdw_cur==0&&rtok==token)||(*pdw_cur==ULONG_MAX&&errno==ERANGE)||(*rtok&&(*rtok!=L'-'||pdw_cur!=&dw_pri))) {
				cnv_err=true;
				break;
			}
			if (*rtok) {
				token=rtok+1;
				pdw_cur=&dw_sec;
			} else {
				if (pdw_cur==&dw_sec) {
					for (DWORD dw_i=dw_pri; uptr_array.push_back(dw_i), dw_i!=dw_sec; dw_pri<=dw_sec?dw_i++:dw_i--);
					pdw_cur=&dw_pri;
				} else
					uptr_array.push_back(dw_pri);
				break;
			}
		}
		if (cnv_err) {
			std::wcerr<<L"Warning: PID list \""<<pid_list<<L"\" is malformed, error in token \""<<token<<L"\"!"<<std::endl;
			uptr_array.clear();
			return false;
		}
	}
	
	//All this hassle with sorting, erasing and following binary_search is to speed up performance with big PID arrays
	//Because intended use for this function is mass PID killing or killing single PIDs from vaguely known range
	std::sort(uptr_array.begin(), uptr_array.end());
	uptr_array.erase(std::unique(uptr_array.begin(), uptr_array.end()), uptr_array.end());
	
	return true;
}

inline bool Killers::PidListCompare(std::vector<ULONG_PTR> &uptr_array, ULONG_PTR pid) 
{
	return std::binary_search(uptr_array.begin(), uptr_array.end(), pid);
}

bool Killers::KillPidsInArray(const wchar_t* arg_parray) 
{
	std::vector<ULONG_PTR> uptr_array;
	
	if (!arg_parray||!PidListPrepare(arg_parray, uptr_array))
		arg_parray=L"";

#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KillPidsInArray:"<<__LINE__<<L": Dumping generated PID list for \""<<arg_parray<<L"\"..."<<std::endl;
	for (ULONG_PTR &uptr_i: uptr_array)
		std::wcerr<<L"\t\t"<<uptr_i<<std::endl;
#endif
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that match PID(s) \"";
	else
		std::wcout<<L"that matches PID(s) \"";
	std::wcout<<arg_parray;
	
	bool found=!uptr_array.empty()&&ApplyToProcesses([this, arg_parray, &uptr_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (PidListCompare(uptr_array, PID)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"\" NOT found"<<std::endl;
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
						qstr<<std::nouppercase<<std::noshowbase<<std::hex<<std::setfill(L'0')<<L"\\StringFileInfo\\"<<std::setw(4)<<plcp->wLanguage<<std::setw(4)<<plcp->wCodePage<<L"\\"<<item_str[0];
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

bool Killers::CheckModListNames(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, bool full, const wchar_t* wcard) 
{
	for (const std::pair<std::wstring, std::wstring> &module: mlist)
		if (MultiWildcardCmp(wcard, full?module.second.c_str():module.first.c_str(), full)) return true;
	
	return false;
}

bool Killers::CheckModListDescriptions(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, const wchar_t** item_str, const wchar_t** desc_str) 
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
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that use Direct3D ";
	else
		std::wcout<<L"that uses Direct3D ";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByD3d:"<<__LINE__<<L": Processing modules for \""<<name<<"\"..."<<std::endl;
#endif
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByD3d:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByOgl(bool param_simple) 
{
	const wchar_t* descA[]={L"OpenGL", NULL, L"MiniGL", NULL, NULL,	L"http://www.mesa3d.org", NULL, NULL};
	const wchar_t* itemA[]={L"FileDescription", NULL,				L"Contact", NULL, NULL};
	
	const wchar_t* wcrdA=L"opengl*.dll;3dfx*gl*.dll";
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that use OpenGL ";
	else
		std::wcout<<L"that uses OpenGL ";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByOgl:"<<__LINE__<<L": Processing modules for \""<<name<<"\"..."<<std::endl;
#endif
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByOgl:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByGld(bool param_simple) 
{
	const wchar_t* descA[]={L"Glide", L"3Dfx Interactive", NULL, NULL};
	const wchar_t* itemA[]={L"FileDescription", NULL, NULL};
	
	const wchar_t* wcrdA=L"glide*.dll";
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that use Glide ";
	else
		std::wcout<<L"that uses Glide ";
	
	bool found=ApplyToProcesses([this, param_simple, &descA, &itemA, wcrdA](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByGld:"<<__LINE__<<L": Processing modules for \""<<name<<"\"..."<<std::endl;
#endif
		std::vector<std::pair<std::wstring, std::wstring>> mlist=FPRoutines::GetModuleList(hProcess);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByGld:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::pair<std::wstring, std::wstring> &module: mlist)
			std::wcerr<<L"\""<<module.first<<L"\" : \""<<module.second<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

//Checks if window is task-window - window that is eligible to be shown in Task Bar and Task Switcher (Alt+Tab)
//N.B.: Ghost windows are also task windows
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

bool Killers::KillByInr(bool param_plus) 
{
	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId returns PID as DWORD

	//Unfortunately, can't use those pretty capture-less lambdas here because of calling conventions
	//By default lambda calling conventions is __cdecl, which is OK on x86-64 because CALLBACK is also __cdecl here
	//But on good old x86 CALLBACK is __stdcall which is incompatible with __cdecl
	//At least we can use tuples so not to litter class definition with structs
	WNDCLASS dummy_wnd;
	std::tuple<bool, std::vector<DWORD>&, ATOM> enum_wnd_tuple(param_plus, dw_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
	//The trick with GetClassInfo is described by Raymond Chen in his blog http://blogs.msdn.com/b/oldnewthing/archive/2004/10/11/240744.aspx
	//Undocumented side of GetClassInfo is that it returns ATOM for the queried window class
	//By passing NULL as HINSTANCE we can get ATOM for the system "Ghost" class
	EnumWindows(EnumWndInr, (LPARAM)&enum_wnd_tuple);
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that are not responding ";
	else
		std::wcout<<L"that is not responding ";
	
	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

BOOL CALLBACK Killers::EnumWndInr(HWND hwnd, LPARAM lParam) 
{
	ATOM ghost_atom=std::get<2>(*(std::tuple<bool, std::vector<DWORD>&, ATOM>*)lParam);
					
	if (IsTaskWindow(hwnd)) {	//Filtering out non-task windows because they can be erroneously reported as hung
		bool plus_version=std::get<0>(*(std::tuple<bool, std::vector<DWORD>&, ATOM>*)lParam);
		std::vector<DWORD> &dw_array=std::get<1>(*(std::tuple<bool, std::vector<DWORD>&, ATOM>*)lParam);

		DWORD pid;

		//This is the way Windows checks if application is hung - using IsHungAppWindow
		//Logic behind IsHungAppWindow considers window hung if it's thread:
		//	isn't waiting for input
		//	isn't in startup processing
		//	hasn't called PeekMessage() within some time interval (5 sec for IsHungAppWindow)
		//The trick is that IsHungAppWindow will return true for both app's own window and it's "ghost" window (that belongs to dwm or explorer)
		//IsHungAppWindow fails to detect apps that were specifically made to be hung (using SuspendThread)
		//But outside test environment it's almost impossible case
		if (IsHungAppWindow(hwnd)) {
			//Check that hung window is not "ghost" window
			//Comparing class name with "Ghost" can be unreliable - application can register it's own local class with that name
			//But outside of enum function we already got ATOM of the actual system "Ghost" class
			//So all we have to do is just compare window class ATOM with "Ghost" class ATOM
			if (GetClassLongPtr(hwnd, GCW_ATOM)!=ghost_atom)
				if (GetWindowThreadProcessId(hwnd, &pid))
					dw_array.push_back(pid);
		} else if (plus_version) {
			//Pretty straightforward method that is suggested by MS https://support.microsoft.com/kb/231844
			//Just wait for SendMessageTimeout to fail - because of abort (if app is hung) or actual timeout
			//This method perfectly detects SuspendThread test apps 
			//It doesn't trigger on "ghost" windows
			//But ironically fails to detect some normal hung apps that trigger IsHungAppWindow
			//That's because internally SMTO_ABORTIFHUNG uses the same mechanism of checking hung windows as IsHungAppWindow but with different time constants
			//While IsHungAppWindow checks if PeekMessage() hasn't been called within 5 sec interval, for SMTO_ABORTIFHUNG this interval is 20 sec
			//So this method is used here as optional supplement for IsHungAppWindow
			if (!SendMessageTimeout(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG|SMTO_BLOCK, INR_TIMEOUT, NULL))
				if (GetWindowThreadProcessId(hwnd, &pid))
					dw_array.push_back(pid);
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
		//Test if disp_array is empty before passing it to EnumWndFsc or some udefined behavior might happen!
		//Same thing with "Ghost" class ATOM as in KillByInr
		WNDCLASS dummy_wnd;
		std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM> enum_wnd_tuple(param_anywnd, param_primary, dw_array, disp_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
		EnumWindows(EnumWndFsc, (LPARAM)&enum_wnd_tuple);
	}
	
	PrintCommonKillPrefix();
	std::wcout<<L"running in fullscreen ";
	
	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

//Don't make tons of empty vector checks - this callback is called for a lot of windows
//Just don't call EnumWindows at first place if display vector is empty
//This will also guarantee that display vector is non-empty in this callback
BOOL CALLBACK Killers::EnumWndFsc(HWND hwnd, LPARAM lParam) 
{
	ATOM ghost_atom=std::get<4>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM>*)lParam);
	
	if (IsTaskWindow(hwnd)&&GetClassLongPtr(hwnd, GCW_ATOM)!=ghost_atom) {	//Filtering out non-task windows and "ghost" windows to speed up the search and not kill dwm/explorer accidentally
		bool any_wnd=std::get<0>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM>*)lParam);
		bool pri_disp=std::get<1>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM>*)lParam);
		std::vector<DWORD> &dw_array=std::get<2>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM>*)lParam);
		std::vector<RECT> &disp_array=std::get<3>(*(std::tuple<bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM>*)lParam);

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

bool Killers::KillByFgd(bool param_anywnd)
{
	DWORD pid;
	WNDCLASS dummy_wnd;
	HWND hwnd=GetForegroundWindow();
	
#if DEBUG>=2
	if (!fnNtUserHungWindowFromGhostWindow) {
		std::wcerr<<L"" __FILE__ ":KillByFgd:"<<__LINE__<<L": NtUserHungWindowFromGhostWindow not found!"<<std::endl;
	}
#endif
	
	//Same thing with "Ghost" class ATOM as in KillByInr
	//In case of foreground app is hung, code below will ensure that we won't accidentially kill actual "ghost" window owner (dwm or explorer)
	if (hwnd&&GetClassLongPtr(hwnd, GCW_ATOM)==GetClassInfo(NULL, L"Ghost", &dummy_wnd)) {
		//Undocumented function that is available starting from Vista
		//Returns HWND of the hung window from "ghost" HWND
		if (fnNtUserHungWindowFromGhostWindow)
			hwnd=fnNtUserHungWindowFromGhostWindow(hwnd);
		else
			hwnd=NULL;
	}

	PrintCommonKillPrefix();
	std::wcout<<L"which window is in foreground ";
	
	//IsTaskWindow() limits the scope and prevents from triggering on dialogs belonging to task-windows
	//But it also protects from accidentially killing explorer or other unrelated background app
	bool found=hwnd&&(param_anywnd||IsTaskWindow(hwnd))&&GetWindowThreadProcessId(hwnd, &pid)&&
		ApplyToProcesses([this, pid](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
			if (pid==PID) {
				if (!applied) std::wcout<<L"FOUND:"<<std::endl;
				KillProcess(PID, name);
				return true;
			} else
				return false;
		});

	if (found)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByWnd(const wchar_t* arg_wcard)
{
	if (!arg_wcard)
		arg_wcard=L"";

	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId returns PID as DWORD

	//Unfortunately, can't use those pretty capture-less lambdas here because of calling conventions
	//By default lambda calling conventions is __cdecl, which is OK on x86-64 because CALLBACK is also __cdecl here
	//But on good old x86 CALLBACK is __stdcall which is incompatible with __cdecl
	//At least we can use tuples so not to litter class definition with structs
	//Same thing with "Ghost" class ATOM as in KillByInr
	WNDCLASS dummy_wnd;
	std::tuple<const wchar_t*, std::vector<DWORD>&, ATOM> enum_wnd_tuple(arg_wcard, dw_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
	if (wcslen(arg_wcard)) EnumWindows(EnumWndWnd, (LPARAM)&enum_wnd_tuple);
	
	PrintCommonKillPrefix();
	std::wcout<<L"which window title matches wildcard \""<<arg_wcard;

	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"\" NOT found"<<std::endl;
		return false;
	}
}

BOOL CALLBACK Killers::EnumWndWnd(HWND hwnd, LPARAM lParam) 
{
	if (IsTaskWindow(hwnd)) {	//Filtering out non-task windows to speed up the search
		const wchar_t* wcard=std::get<0>(*(std::tuple<const wchar_t*, std::vector<DWORD>&, ATOM>*)lParam);
		std::vector<DWORD> &dw_array=std::get<1>(*(std::tuple<const wchar_t*, std::vector<DWORD>&, ATOM>*)lParam);
		ATOM ghost_atom=std::get<2>(*(std::tuple<const wchar_t*, std::vector<DWORD>&, ATOM>*)lParam);
		
		HWND real_hwnd=hwnd;
		
		if (GetClassLongPtr(hwnd, GCW_ATOM)==ghost_atom) {
			if (fnNtUserHungWindowFromGhostWindow)
				real_hwnd=fnNtUserHungWindowFromGhostWindow(hwnd);
			else
				return true;
		}
		
		if (int title_len=GetWindowTextLength(hwnd)) {
			wchar_t title_buf[title_len+1];
			DWORD pid;
			if (GetWindowText(hwnd, title_buf, title_len+1)&&
				MultiWildcardCmp(wcard, title_buf, false, NULL)&&
				GetWindowThreadProcessId(real_hwnd, &pid))
				dw_array.push_back(pid);
		}
	}

	return true;
}

bool Killers::CheckProcessUserName(ULONG_PTR PID, const wchar_t* wcard, bool incl_domain)
{
	bool res=false;

	if (HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION)) {
		HANDLE hToken;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			DWORD dwSize;
			if(PTOKEN_USER ptu=GetTokenUserInformation(hToken)) {
				DWORD account_len=0;
				DWORD domain_len=0;
				SID_NAME_USE sid_type;
				if (LookupAccountSid(NULL, ptu->User.Sid, NULL, &account_len, NULL, &domain_len, &sid_type)==FALSE&&account_len&&domain_len) {
					wchar_t account[account_len];
					wchar_t domain[domain_len];
					if (LookupAccountSid(NULL, ptu->User.Sid, account, &account_len, domain, &domain_len, &sid_type)) {
#if DEBUG>=3
						std::wcerr<<L"" __FILE__ ":CheckProcessUserName:"<<__LINE__<<L": DOMAIN=\""<<domain<<"\" USER=\""<<account<<"\""<<std::endl;
#endif
						if (incl_domain) {
							std::wstring fname(domain);
							fname.push_back(L'\\');
							fname.append(account);
							res=MultiWildcardCmp(wcard, fname.c_str(), true, L";,");
						} else {
							res=MultiWildcardCmp(wcard, account, false, L";,");
						}
					}
				}
				
				FreeTokenUserInformation(ptu);
			}
			
			CloseHandle(hToken);
		}

		CloseHandle(hProcess);
	}
	
	return res;
}

bool Killers::KillByUsr(bool param_full, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	PrintCommonKillPrefix();
	std::wcout<<L"which user name match wildcard(s) \""<<arg_wcard;
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByUsr:"<<__LINE__<<L": Getting user name for \""<<name<<"\"..."<<std::endl;
#endif	
		if (CheckProcessUserName(PID, arg_wcard, param_full)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name);
			return true;
		} else
			return false;
	});

	if (found)
		return true;
	else {
		std::wcout<<L"\" NOT found"<<std::endl;
		return false;
	}
}
