#include "Killers.h"
#include "FilePathRoutines.h"
#include "Externs.h"
#include "Common.h"
#include "Res.h"
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

//These are also defined in windows.h in ifdef OEMRESOURCE clause
//#define SNK_OCR_SIZE 32640	//OBSOLETE: use OCR_SIZEALL
//#define SNK_OCR_ICON 32641	//OBSOLETE: use OCR_NORMAL
//#define SNK_OCR_ICOCUR 32647	//OBSOLETE: use OIC_WINLOGO
#define SNK_OCR_NORMAL 32512
#define SNK_OCR_IBEAM 32513
#define SNK_OCR_WAIT 32514
#define SNK_OCR_CROSS 32515
#define SNK_OCR_UP 32516
#define SNK_OCR_SIZENWSE 32642
#define SNK_OCR_SIZENESW 32643
#define SNK_OCR_SIZEWE 32644
#define SNK_OCR_SIZENS 32645
#define SNK_OCR_SIZEALL 32646
#define SNK_OCR_NO 32648
#define SNK_OCR_HAND 32649
#define SNK_OCR_APPSTARTING 32650
#define SNK_OCR_HELP 32651

extern pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow;
extern pGetProcessMemoryInfo fnGetProcessMemoryInfo;
extern pCreateProcessWithTokenW fnCreateProcessWithTokenW;

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

Killers::Killers():
	file_type(0xFFFFFFFF)
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

void Killers::KillProcess(DWORD PID, const std::wstring &name, const std::wstring &path) 
{
	if (ModeBlank()) {
		if (ModeBlacklist())
			std::wcout<<PID<<L" ("<<name<<L") - blacklisted"<<std::endl;
		else if (ModeWhitelist())
			std::wcout<<PID<<L" ("<<name<<L") - whitelisted"<<std::endl;
		else
			std::wcout<<PID<<L" ("<<name<<L")"<<std::endl;
	} else {
		bool mode_restart=ModeRestart();
		std::unique_ptr<wchar_t[]> cmdline;
		std::unique_ptr<wchar_t[]> cwdpath;
		std::unique_ptr<BYTE[]> envblock;
		HANDLE hDupToken=NULL;
		bool go_no_token=false;
		
#if DEBUG>=2		
		if (!fnCreateProcessWithTokenW&&mode_restart) {
			std::wcerr<<L"" __FILE__ ":DoRestart:"<<__LINE__<<L": CreateProcessWithTokenW not found!"<<std::endl;
		}
#endif
		
		//If restart mode is enabled - restart only processes w/ valid path, command line, current working directory, environment block and accessible token
		if (mode_restart&&path.length()) {
			if (HANDLE hPidProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ)) {
				if (FPRoutines::GetCmdCwdEnv(hPidProcess, cmdline, cwdpath, envblock)) {
					HANDLE hOwnToken;
					if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hOwnToken)) {
						if (PTOKEN_USER own_tu=GetTokenUserInformation(hOwnToken)) {
							HANDLE hPidToken;
							if (OpenProcessToken(hPidProcess, TOKEN_QUERY|TOKEN_DUPLICATE, &hPidToken)) {
								if (PTOKEN_USER pid_tu=GetTokenUserInformation(hPidToken)) {
									//TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE and TOKEN_QUERY are needed for both CreateProcessAsUser and CreateProcessWithTokenW
									//CreateProcessWithTokenW also requires TOKEN_ADJUST_DEFAULT and TOKEN_ADJUST_SESSIONID (though documentation doesn't mention this)
									DWORD dwDesiredAccess=TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_QUERY;
									if (fnCreateProcessWithTokenW) dwDesiredAccess|=TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID;
									DuplicateTokenEx(hPidToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenPrimary, &hDupToken);

									go_no_token=EqualSid(own_tu->User.Sid, pid_tu->User.Sid)&&IsTokenElevated(hOwnToken)==IsTokenElevated(hPidToken)&&IsTokenRestrictedEx(hPidToken)==IsTokenRestrictedEx(hOwnToken);

									FreeTokenUserInformation(pid_tu);
								}
								CloseHandle(hPidToken);
							}
							FreeTokenUserInformation(own_tu);
						}
						CloseHandle(hOwnToken);
					}
				}
				CloseHandle(hPidProcess);
			}
		}

		if (!ModeClose()||EnumWindows(EnumWndClose, (LPARAM)PID)||GetLastError()) {
			HANDLE hProcess;
			//PROCESS_TERMINATE is needed for TerminateProcess
			if ((hProcess=OpenProcessWrapper(PID, PROCESS_TERMINATE))&&TerminateProcess(hProcess, 1)) {
				std::wcout<<PID<<L" ("<<name<<L") - killed";
			} else {
				mode_restart=false;
				std::wcout<<PID<<L" ("<<name<<L") - can't be terminated";
			}
			if (hProcess) CloseHandle(hProcess);
		} else
			std::wcout<<PID<<L" ("<<name<<L") - closed";
		
		if (mode_restart) {
			PROCESS_INFORMATION pi={};
			STARTUPINFO si={sizeof(STARTUPINFO), NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, STARTF_USESHOWWINDOW, SW_SHOWNORMAL};
			bool do_restart=false;
				
			if (fnCreateProcessWithTokenW&&hDupToken) {
				//SE_IMPERSONATE_NAME, needed for CreateProcessWithTokenW, is default enabled for elevated admin and can't be set without elevation (Local Sytem is similar to elevated admin)
				//Even with token identical to own token, SE_IMPERSONATE_NAME is still needed for CreateProcessWithTokenW
				//If SE_IMPERSONATE_NAME is not set, CreateProcessWithTokenW will try to set it on it's own
				do_restart=fnCreateProcessWithTokenW(hDupToken, 0, path.c_str(), cmdline.get(), CREATE_SUSPENDED|NORMAL_PRIORITY_CLASS|CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT, envblock.get(), cwdpath.get(), &si, &pi);
			} 
			
			if (!do_restart&&hDupToken) {
				//CreateProcessAsUser requires SE_INCREASE_QUOTA_NAME and also typically requires SE_ASSIGNPRIMARYTOKEN_NAME, with latter being available only to Local System
				//Before Vista it was sufficient to impersonate Local System for this privilege to work, but since Vista this trick won't work anymore
				//Fortunately here we have CreateProcessWithTokenW that doesn't require Local System privileges
				//Also documentation states that restricted version of own token can be used with CreateProcessAsUser without setting SE_ASSIGNPRIMARYTOKEN_NAME privilege
				//Unfortunately tests show that SE_ASSIGNPRIMARYTOKEN_NAME is still needed for restricted tokens, at least the ones created by disabling SIDs
				//But SE_ASSIGNPRIMARYTOKEN_NAME not needed when CreateProcessAsUser is used with token identical to own token
				//If SE_INCREASE_QUOTA_NAME or SE_ASSIGNPRIMARYTOKEN_NAME is not set, CreateProcessAsUser will try to set it on it's own
				do_restart=CreateProcessAsUser(hDupToken, path.c_str(), cmdline.get(), NULL, NULL, FALSE, CREATE_SUSPENDED|NORMAL_PRIORITY_CLASS|CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT, envblock.get(), cwdpath.get(), &si, &pi);
			} 
			
			if (!do_restart&&go_no_token) {
				//In case where we failed to duplicate token or CreateProcessWithTokenW and CreateProcessAsUser failed - check if we can use ordinary CreateProcess
				//We can use it only if PID token is similar to own token so not to grant any additional rights to PID token (or withhold rights) or change SIDs
				//Proper check would be to completely compare both tokens, but this is actually an overkill - tokens are likely to be mostly equal if owner SID is the same one
				//Here we are just check if PID token belongs to the same owner SID and have the same level elevation and (almost the same) restrictions, which are the most common cases of dissimilarities between tokens from the same owner
				do_restart=CreateProcess(path.c_str(), cmdline.get(), NULL, NULL, FALSE, CREATE_SUSPENDED|NORMAL_PRIORITY_CLASS|CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT, envblock.get(), cwdpath.get(), &si, &pi);
			}
				
			if (do_restart) 
				RestartProcess(pi.hProcess, pi.hThread);
			else			
				std::wcout<<L", can't be restarted";
		}
		
		if (hDupToken) CloseHandle(hDupToken);
		
		std::wcout<<std::endl;
	}
}


BOOL CALLBACK Killers::EnumWndClose(HWND hwnd, LPARAM lParam) 
{
	DWORD pid;
	if ((GetWindowThreadProcessId(hwnd, &pid), pid)==(DWORD)lParam) {	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
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
		KillProcess(PID, name, path);
		return true;
	});
	
	if (found) {
		return true;
	} else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

void Killers::PrintCommonWildcardInfix(const wchar_t* arg_wcard, const wchar_t* delim)
{
	if (wcspbrk(arg_wcard, delim))
		std::wcout<<L"wildcards \"";
	else
		std::wcout<<L"wildcard \"";
	std::wcout<<arg_wcard;
}

bool Killers::KillByPth(bool param_full, bool param_strict, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	PrintCommonKillPrefix();
	if (ModeLoop())
		std::wcout<<L"that match ";
	else
		std::wcout<<L"that matches ";
	PrintCommonWildcardInfix(arg_wcard);
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, param_strict, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		//PData.path not necessary have valid path - it can be empty if FPRoutines::GetFilePath failed during process enumeration (Processes::RequestPopulatedCAN)
		if ((param_full?path.length():true)&&MultiWildcardCmp(arg_wcard, param_full?path.c_str():name.c_str(), param_strict?MWC_PTH:MWC_STR)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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

bool Killers::KillByMod(bool param_full, bool param_strict, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	PrintCommonKillPrefix();
	std::wcout<<L"having modules that match ";
	PrintCommonWildcardInfix(arg_wcard);
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, param_strict, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ);
		if (!hProcess) return false;
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByMod:"<<__LINE__<<L": Processing modules for \""<<name<<L"\"..."<<std::endl;
#endif
		std::vector<std::wstring> mlist=FPRoutines::GetModuleList(hProcess, param_full);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByMod:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::wstring &module: mlist)
			std::wcerr<<L"\t\""<<module<<L"\""<<std::endl;
#endif

		if (CheckModListNames(mlist, param_strict, arg_wcard)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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

bool Killers::KillByPid(const wchar_t* arg_parray) 
{
	std::vector<ULONG_PTR> uptr_array;
	
	if (!arg_parray||!PidListPrepare(arg_parray, uptr_array))
		arg_parray=L"?";

#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KillPidsInArray:"<<__LINE__<<L": Dumping generated PID list for "<<arg_parray<<L"..."<<std::endl;
	for (ULONG_PTR &uptr_i: uptr_array)
		std::wcerr<<L"\t\t"<<uptr_i<<std::endl;
#endif
	
	if (uptr_array.size()>1) {
		PrintCommonKillPrefix();
		if (ModeLoop())
			std::wcout<<L"that match PIDs ";
		else
			std::wcout<<L"that matches PIDs ";
	} else {
		if (ModeAll())
			std::wcout<<L"Process that matches PID ";
		else
			std::wcout<<L"User process that matches PID ";	
	}
	std::wcout<<arg_parray<<L' ';
	
	bool found=!uptr_array.empty()&&ApplyToProcesses([this, &uptr_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (PidListCompare(uptr_array, PID)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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

bool Killers::CheckModListNames(const std::vector<std::wstring> &mlist, bool strict, const wchar_t* wcard) 
{
	for (const std::wstring &module: mlist)
		if (MultiWildcardCmp(wcard, module.c_str(), strict?MWC_PTH:MWC_STR)) return true;
	
	return false;
}

bool Killers::CheckModListDescriptions(const std::vector<std::wstring> &mlist, const wchar_t** item_str, const wchar_t** desc_str) 
{
	for (const std::wstring &module: mlist)
		if (CheckStringFileInfo(module.c_str(), item_str, desc_str)) return true;
	
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
		std::vector<std::wstring> mlist=FPRoutines::GetModuleList(hProcess, !param_simple);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByD3d:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::wstring &module: mlist)
			std::wcerr<<L"\t\""<<module<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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
		std::vector<std::wstring> mlist=FPRoutines::GetModuleList(hProcess, !param_simple);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByOgl:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::wstring &module: mlist)
			std::wcerr<<L"\t\""<<module<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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
		std::vector<std::wstring> mlist=FPRoutines::GetModuleList(hProcess, !param_simple);
		CloseHandle(hProcess);
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByGld:"<<__LINE__<<L": Dumping modules for \""<<name<<"\"..."<<std::endl;
		for (const std::wstring &module: mlist)
			std::wcerr<<L"\t\""<<module<<L"\""<<std::endl;
#endif
		
		if (param_simple?CheckModListNames(mlist, false, wcrdA):CheckModListDescriptions(mlist, itemA, descA)) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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
//N.B. Ghost windows are also task windows
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

#define InrTuple std::tuple<bool, std::vector<DWORD>&, ATOM>
bool Killers::KillByInr(bool param_plus) 
{
	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId returns PID as DWORD

	//Unfortunately, can't use those pretty capture-less lambdas here because of calling conventions
	//By default lambda calling conventions is __cdecl, which is OK on x86-64 because CALLBACK is also __cdecl here
	//But on good old x86 CALLBACK is __stdcall which is incompatible with __cdecl
	//At least we can use tuples so not to litter class definition with structs
	WNDCLASS dummy_wnd;
	InrTuple enum_wnd_tuple(param_plus, dw_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
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
			KillProcess(PID, name, path);
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
	ATOM ghost_atom=std::get<2>(*(InrTuple*)lParam);
					
	if (IsTaskWindow(hwnd)) {	//Filtering out non-task windows because they can be erroneously reported as hung
		bool plus_version=std::get<0>(*(InrTuple*)lParam);
		std::vector<DWORD> &dw_array=std::get<1>(*(InrTuple*)lParam);

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
				if ((GetWindowThreadProcessId(hwnd, &pid), pid))	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
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
				if ((GetWindowThreadProcessId(hwnd, &pid), pid))	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
					dw_array.push_back(pid);
		}
	}
	
	return TRUE;
}

#define FscTuple std::tuple<bool, bool, bool, std::vector<DWORD>&, std::vector<RECT>&, ATOM, DWORD&>
bool Killers::KillByFsc(bool param_anywnd, bool param_primary, bool param_strict) 
{
	std::vector<DWORD> dw_array;	//DWORD PID because GetWindowThreadProcessId return PID as DWORD
	DWORD cur_max_area=0;
	std::vector<RECT> disp_array;
	
	//So what's the deal with EnumDisplayDevicesWrapper and Duff's Device?
	//EnumDisplayDevices takes 4 parameters and iDevNum starts at 0
	//But not on NT4 - here it will take 3 parameters and iDevNum starts at 1
	//Detecting OS version, importing EnumDisplayDevices with proper prototype and dealing with these cases separately - no fun
	//Duff's Device will check both iDevNum start positions
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
		FscTuple enum_wnd_tuple(param_anywnd, param_primary, param_strict, dw_array, disp_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd), cur_max_area);
		EnumWindows(EnumWndFsc, (LPARAM)&enum_wnd_tuple);
	}
	
	PrintCommonKillPrefix();
	std::wcout<<L"running in fullscreen ";
	
	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			if (!applied) std::wcout<<L"FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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
	ATOM ghost_atom=std::get<5>(*(FscTuple*)lParam);
	
	//IsTaskWindow is a must here because even with less strict IsWindowVisible (or no filtering at all) we will count as "fullscreen" some technical windows like explorer's one
	if (IsTaskWindow(hwnd)&&GetClassLongPtr(hwnd, GCW_ATOM)!=ghost_atom) {	//Filtering out non-task windows and "ghost" windows to speed up the search and not kill dwm/explorer accidentally
		bool any_wnd=std::get<0>(*(FscTuple*)lParam);
		bool pri_disp=std::get<1>(*(FscTuple*)lParam);
		bool strict=std::get<2>(*(FscTuple*)lParam);
		std::vector<DWORD> &dw_array=std::get<3>(*(FscTuple*)lParam);
		std::vector<RECT> &disp_array=std::get<4>(*(FscTuple*)lParam);
		DWORD &cur_max_area=std::get<6>(*(FscTuple*)lParam);

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
				DWORD pid;
				bool add=false;
				if (disp_array.size()==1) {
					//If we have only one display - use more relaxed algorithm
					//Some fullscreen game windows have their coordinates unaligned with display (e.g. Valkyria Chronicles)
					//Some fullscreen game windows have size greater than display size
					//So just check that app's window size is greater or equal to display size
					if (window_rect.right-window_rect.left>=disp_array[0].right-disp_array[0].left&&window_rect.bottom-window_rect.top>=disp_array[0].bottom-disp_array[0].top)
						if ((GetWindowThreadProcessId(hwnd, &pid), pid)) add=true;	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
				} else {
					//Relaxed algorithm that is suitable for single display can cause false positive on multiple displays
					//For multiple displays test if app's RECT contains at least one of the displays' RECT to consider it fullscreen app
					//Still, games for which relaxed algorithm works best behave the same on multiple displays and therefore will not be considered fullscreen there
					//In this case KillByFgd is more suitable
					if (pri_disp
						?WithinRect(window_rect, disp_array[0])
						:std::any_of(disp_array.begin(), disp_array.end(), std::bind(WithinRect, window_rect, std::placeholders::_1)))
						if ((GetWindowThreadProcessId(hwnd, &pid), pid)) add=true;	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
				}
				
				if (add) {
#if DEBUG>=3
					std::wcerr<<L"" __FILE__ ":EnumWndFsc:"<<__LINE__<<L": ADDED PID("<<pid<<L") HWND("<<std::hex<<(ULONG_PTR)hwnd<<std::dec<<L") - CRECT=("
						<<client_rect.left<<L","<<client_rect.top<<L")("<<client_rect.right<<L","<<client_rect.bottom<<L") - WRECT=("
						<<window_rect.left<<L","<<window_rect.top<<L")("<<window_rect.right<<L","<<window_rect.bottom<<L")"<<std::endl;
#endif
					if (strict) {
						//By convention, the right and bottom edges of the rectangle are normally considered exclusive
						//So the pixel with (right, bottom) coordinates lies immediately outside of the rectangle
						DWORD area=(window_rect.right-window_rect.left)*(window_rect.bottom-window_rect.top);
						if (area==cur_max_area) {
							dw_array.push_back(pid);
						} else if (area>cur_max_area) {
							cur_max_area=area;
							dw_array.clear();
							dw_array.push_back(pid);
						}
					} else {
						dw_array.push_back(pid);
					}
				}
			}
		}
	}

	return TRUE;
}

bool Killers::KillByFgd()
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

	if (ModeAll())
		std::wcout<<L"Process which window is in foreground ";
	else
		std::wcout<<L"User process which window is in foreground ";
	
	bool found=hwnd&&(GetWindowThreadProcessId(hwnd, &pid), pid)&&	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
		ApplyToProcesses([this, pid](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
			if (pid==PID) {
				if (!applied) std::wcout<<L"FOUND:"<<std::endl;
				KillProcess(PID, name, path);
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

#define WndTuple std::tuple<const wchar_t*, std::vector<DWORD>&, ATOM>
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
	WndTuple enum_wnd_tuple(arg_wcard, dw_array, GetClassInfo(NULL, L"Ghost", &dummy_wnd));
	EnumWindows(EnumWndWnd, (LPARAM)&enum_wnd_tuple);
	
	PrintCommonKillPrefix();
	std::wcout<<L"which window title matches wildcard \""<<arg_wcard;

	bool found=!dw_array.empty()&&ApplyToProcesses([this, &dw_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(dw_array.begin(), dw_array.end(), PID)!=dw_array.end()) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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
	if (IsWindowVisible(hwnd)) {	//Filtering out non-visible windows to speed up the search
		const wchar_t* wcard=std::get<0>(*(WndTuple*)lParam);
		std::vector<DWORD> &dw_array=std::get<1>(*(WndTuple*)lParam);
		ATOM ghost_atom=std::get<2>(*(WndTuple*)lParam);
				
		HWND real_hwnd=hwnd;
		
		//Why not filtering out ghost windows completely?
		//If not filtering it out, assuming that NtUserHungWindowFromGhostWindow is available, we will add two identical PIDs (for ghost window and original one)
		//This may look that something that we don't want
		//But user may supply something like "*(Not Responding)" for wcard in hope for killing hung application
		//That's why we are also querying ghost windows
		if (GetClassLongPtr(hwnd, GCW_ATOM)==ghost_atom) {
			if (fnNtUserHungWindowFromGhostWindow)
				real_hwnd=fnNtUserHungWindowFromGhostWindow(hwnd);
			else
				return TRUE;
		}
		
		bool wcard_matched=false;
		if (int title_len=GetWindowTextLength(hwnd)) {
			wchar_t title_buf[title_len+1];
			if (GetWindowText(hwnd, title_buf, title_len+1)&&MultiWildcardCmp(wcard, title_buf, MWC_STR, NULL))
				wcard_matched=true;
		} else if (GetLastError()==ERROR_SUCCESS) {	//Empty window title is also title
			if (MultiWildcardCmp(wcard, L"", MWC_STR, NULL))
				wcard_matched=true;
		}
		
		DWORD pid;
		if (wcard_matched&&(GetWindowThreadProcessId(real_hwnd, &pid), pid)) {	//See note on GetWindowThreadProcessId in Killers::MouseHookAim
#if DEBUG>=3
			std::wcerr<<L"" __FILE__ ":EnumWndWnd:"<<__LINE__<<L": PID("<<pid<<L") HWND("<<std::hex<<(ULONG_PTR)hwnd<<std::dec<<L")"<<std::endl;
#endif
			dw_array.push_back(pid);
		}
	}

	return TRUE;
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
							res=MultiWildcardCmp(wcard, fname.c_str(), MWC_PTH, L";,");
						} else {
							res=MultiWildcardCmp(wcard, account, MWC_STR, L";,");
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
	std::wcout<<L"which user name matches ";
	PrintCommonWildcardInfix(arg_wcard, L";,");
	
	bool found=wcslen(arg_wcard)&&ApplyToProcesses([this, param_full, arg_wcard](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":KillByUsr:"<<__LINE__<<L": Getting user name for \""<<name<<"\"..."<<std::endl;
#endif	
		if (CheckProcessUserName(PID, arg_wcard, param_full)) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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

bool Killers::KillByMem(bool param_vm, const wchar_t* arg_maxmem)
{
	if (!arg_maxmem)
		arg_maxmem=L"";

	bool found_noerr=true;
	bool top_mem=false;
	SIZE_T st_maxmem;
	
	if (*arg_maxmem==L'\0') {
		top_mem=true;
	} else {
		wchar_t* endptr;
#ifdef _WIN64
		st_maxmem=wcstoull(arg_maxmem, &endptr, 10);
		if (*arg_maxmem==L'-'||*endptr!=L'\0'||(st_maxmem==ULLONG_MAX&&errno==ERANGE)||st_maxmem>ULLONG_MAX/1024) {
#else
		st_maxmem=wcstoul(arg_maxmem, &endptr, 10);
		if (*arg_maxmem==L'-'||*endptr!=L'\0'||(st_maxmem==ULONG_MAX&&errno==ERANGE)||st_maxmem>ULONG_MAX/1024) {
#endif
			found_noerr=false;
			std::wcerr<<L"Warning: target memory usage \""<<arg_maxmem<<L"\" is malformed!"<<std::endl;
			arg_maxmem=L"?";
		}
	}
	
	PrintCommonKillPrefix();
	if (ModeLoop()) {
		if (top_mem)
			std::wcout<<L"with highest memory usage ";
		else
			std::wcout<<L"with memory usage higher than "<<arg_maxmem<<L" KB ";
	} else {
		if (top_mem)
			std::wcout<<L"and highest memory usage ";
		else
			std::wcout<<L"and memory usage higher than "<<arg_maxmem<<L" KB ";
	}
	
	if (found_noerr) {
#if DEBUG>=2
		if (!fnGetProcessMemoryInfo)
			std::wcerr<<L"" __FILE__ ":KillByMem:"<<__LINE__<<L": GetProcessMemoryInfo not found!"<<std::endl;
#endif

		std::vector<std::tuple<ULONG_PTR, std::wstring, std::wstring>> pid_array;
		SIZE_T cur_highest_mem=0;
		
		found_noerr=fnGetProcessMemoryInfo&&ApplyToProcesses([this, top_mem, param_vm, st_maxmem, &cur_highest_mem, &pid_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
			bool triggered=false;

			if (HANDLE hProcess=OpenProcessWrapper(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, PROCESS_VM_READ)) {
				PROCESS_MEMORY_COUNTERS pmc={sizeof(PROCESS_MEMORY_COUNTERS)};
				if (fnGetProcessMemoryInfo(hProcess, &pmc, sizeof(PROCESS_MEMORY_COUNTERS))) {
#if DEBUG>=3
					std::wcerr<<L"" __FILE__ ":KillByMem:"<<__LINE__<<L": Mem usage for "<<PID<<L" ("<<name<<L"): WorkingSetSize="<<pmc.WorkingSetSize<<L" PagefileUsage="<<pmc.PagefileUsage<<std::endl;
#endif
					SIZE_T cur_mem=param_vm?pmc.PagefileUsage:pmc.WorkingSetSize;
					if (top_mem) {
						if (cur_mem==cur_highest_mem) {
							pid_array.push_back(std::make_tuple(PID, name, path));
						} else if (cur_mem>cur_highest_mem) {
							cur_highest_mem=cur_mem;
							pid_array.clear();
							pid_array.push_back(std::make_tuple(PID, name, path));
						}							
					} else if (cur_mem>st_maxmem*1024) {
						if (!applied) std::wcout<<L"FOUND:"<<std::endl;
						KillProcess(PID, name, path);
						triggered=true;
					}
				}
				CloseHandle(hProcess);
			}

			return triggered;
		});
		
		if (top_mem) {
			for (const std::tuple<ULONG_PTR, std::wstring, std::wstring> &pid_data: pid_array) {
				if (!found_noerr) std::wcout<<L"FOUND:"<<std::endl;
				KillProcess(std::get<0>(pid_data), std::get<1>(pid_data), std::get<2>(pid_data));
				found_noerr=true;
				if (!ModeLoop()) break;
			}
		}
	}

	if (found_noerr)
		return true;
	else {
		std::wcout<<L"NOT found"<<std::endl;
		return false;
	}
}

bool Killers::KillByAim()
{
	//Set all the system cursors to crosshair
	DWORD sys_cursors[]={SNK_OCR_APPSTARTING, SNK_OCR_NORMAL, SNK_OCR_CROSS, SNK_OCR_HAND, SNK_OCR_HELP, SNK_OCR_IBEAM, SNK_OCR_NO, SNK_OCR_SIZEALL, SNK_OCR_SIZENESW, SNK_OCR_SIZENS, SNK_OCR_SIZENWSE, SNK_OCR_SIZEWE, SNK_OCR_UP, SNK_OCR_WAIT};
	if (HCURSOR hLocalCursor=LoadCursor(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_CROSSHAIR)))
		for (DWORD sys_cur: sys_cursors)
			if (HCURSOR hCursorCopy=CopyCursor(hLocalCursor))
				SetSystemCursor(hCursorCopy, sys_cur);
	
	DWORD aim_pid=0;
	if (HHOOK ms_hook=SetWindowsHookEx(WH_MOUSE_LL, MouseHookAim, GetModuleHandle(NULL), 0)) {		
		//For hook to work thread should have message loop, though it can be pretty castrated
		//Only GetMessage is needed because hook callback is actually called inside this one function
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0)); //See https://blogs.msdn.microsoft.com/oldnewthing/20130322-00/?p=4873
		aim_pid=msg.wParam;
		
		UnhookWindowsHookEx(ms_hook);
	}
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KillByAim:"<<__LINE__<<L": AIM_PID="<<aim_pid<<std::endl;
#endif
	
	//Restore system cursors
	SystemParametersInfo(SPI_SETCURSORS, 0, NULL, 0);
	
	if (ModeAll())
		std::wcout<<L"Targeted process ";
	else
		std::wcout<<L"Targeted user process ";
	
	bool found=aim_pid&&ApplyToProcesses([this, aim_pid](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
			if (aim_pid==PID) {
				if (!applied) std::wcout<<L"FOUND:"<<std::endl;
				KillProcess(PID, name, path);
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

LRESULT CALLBACK Killers::MouseHookAim(int nCode, WPARAM wParam, LPARAM lParam)
{
	//HOOKPROC requires that on less-than-zero nCode CallNextHookEx should be returned immediately
	//We should return non-zero value if event shouldn't be passed further down the mouse handlers chain
	if (nCode>=0) switch (wParam) {
		case WM_LBUTTONUP:
		case WM_RBUTTONUP:
			{
				DWORD aim_pid=0;
				if (wParam==WM_LBUTTONUP) {
					//Note on GetWindowThreadProcessId
					//Inside it PID and TID values are acquired by separate but similar means
					//If GetWindowThreadProcessId failed to acquired TID it will still try to acquire PID (assuming lpdwProcessId is not NULL) and vice versa
					//So, theoretically, if TID is 0 it doesn't mean that PID is also 0
					//But the odds are so low as to be negligible, though if what you need is really PID - it's logically to check if PID is 0 and not returned TID
					//And what definetley is not negligible is that supplied PID variable will be overwritten in any case - with true PID or with 0 in case of error
					//N.B. MSDN does a nice thing and doesn't state that if GetWindowThreadProcessId returned 0 it means error
					if (HWND aim_wnd=WindowFromPoint(((MSLLHOOKSTRUCT*)lParam)->pt))
						GetWindowThreadProcessId(aim_wnd, &aim_pid);
				}
				PostThreadMessage(GetCurrentThreadId(), WM_QUIT, aim_pid, 0);
			}
		default:
			return 1;
		case WM_MOUSEMOVE:
			break;
	}
	
	//Let CallNextHookEx handle everything else
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

#define OflTuple std::tuple<HANDLE, HANDLE, HANDLE*, bool*>
bool Killers::KillByOfl(bool param_full, bool param_strict, const wchar_t* arg_wcard) 
{
	if (!arg_wcard)
		arg_wcard=L"";
	
	std::vector<ULONG> ul_array;	//ULONG PID because SYSTEM_HANDLE_ENTRY.OwnerPid is ULONG
	
	if (wcslen(arg_wcard)) {
		SYSTEM_HANDLE_INFORMATION *pshi;
		HANDLE h_ownexe=INVALID_HANDLE_VALUE;
		
		//If file object type is not known yet - open own executable
		if (file_type==0xFFFFFFFF) {
			//MAX_PATH related issues is a tough question regarding loading modules
			//At present (Win 10) it seems that LoadLibrary and CreateProcess really doesn't handle path lengths more than MAX_PATH
			//Current workaround is converting such paths to short "8.3" format and using it with aforementioned functions
			//In this case paths returned by GetModuleFileName won't exceed MAX_PATH because they will be in 8.3 format
			//(for executable, modules loaded from executable directory and modules loaded with 8.3 paths)
			wchar_t exe_path[MAX_PATH];
			DWORD retlen=GetModuleFileName(NULL, exe_path, MAX_PATH);
			//GetModuleFileName returns 0 if everything is bad and nSize (which is MAX_PATH) if buffer size is insufficient and returned path truncated
			if (retlen&&retlen<MAX_PATH)
				h_ownexe=CreateFile(exe_path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		}
		
		//If file object type is not known yet - clean cache so exe handle will be included in system handle enumeration
		if (CachedNtQuerySystemHandleInformation(&pshi, file_type==0xFFFFFFFF)&&pshi->Count) {
			ULONG entry_idx;
			//If file object type is not known yet - search for it
			if (file_type==0xFFFFFFFF) {
				//Search SYSTEM_HANDLE_INFORMATION for exe handle to get right SYSTEM_HANDLE_ENTRY.ObjectType for file
				//Search is carried out from the end because new handles are appended to the end of the list and so are the handles for just launched current process
				DWORD pid=GetCurrentProcessId();
				entry_idx=pshi->Count;
				do {
					entry_idx--;
					if ((HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue==h_ownexe&&pshi->Handle[entry_idx].OwnerPid==pid) {
						file_type=pshi->Handle[entry_idx].ObjectType;
						break;
					}
				} while (entry_idx);
			}
			
			//Search SYSTEM_HANDLE_INFORMATION for file that match arg_wcard
			ULONG prc_pid=0;
			HANDLE hProcess=NULL;
			HANDLE cur_prc=GetCurrentProcess();
			HANDLE hDupFile;
			HANDLE get_type_event=CreateEvent(NULL, FALSE, FALSE, NULL);
			HANDLE ready_event=CreateEvent(NULL, FALSE, FALSE, NULL);
			bool is_disk_file;
			OflTuple thread_tuple(get_type_event, ready_event, &hDupFile, &is_disk_file);
			HANDLE gft_thread=CreateThread(NULL, 0, ThreadGetFileType, (LPVOID)&thread_tuple, CREATE_SUSPENDED, NULL);
			SetThreadPriority(gft_thread, THREAD_PRIORITY_TIME_CRITICAL);	//Set higher priority for GetFileType thread because it would be tested for timeout
			ResumeThread(gft_thread);
			
			for (entry_idx=0; entry_idx<pshi->Count; entry_idx++) if (pshi->Handle[entry_idx].ObjectType==file_type) {
				//To speed up enumeration - cache opened process handle
				if (prc_pid!=pshi->Handle[entry_idx].OwnerPid) {
					prc_pid=pshi->Handle[entry_idx].OwnerPid;
					if (hProcess) CloseHandle(hProcess);
					hProcess=OpenProcessWrapper(prc_pid, PROCESS_DUP_HANDLE);
#if DEBUG>=3
					std::wcerr<<L"" __FILE__ ":KillByOfl:"<<__LINE__<<L": Handles for PID "<<prc_pid<<std::endl;
#endif
				}
				if (hProcess&&DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)pshi->Handle[entry_idx].HandleValue, cur_prc, &hDupFile, 0, FALSE, DUPLICATE_SAME_ACCESS)) {		
					//NtQueryObject and NtQueryInformationFile (used in FPRoutines::GetHandlePath) hang on pipe handles
					//NtQueryInformationFile fails on most non-FILE_TYPE_DISK handles
					//And we dont't need pipes and other non-FILE_TYPE_DISK handles actually
					
					SetEvent(get_type_event);
					if (WaitForSingleObject(ready_event, 1000)==WAIT_TIMEOUT) {
#if DEBUG>=3
						std::wcerr<<L"" __FILE__ ":KillByOfl:"<<__LINE__<<L": GetFileType hanged on "<<std::hex<<(ULONG_PTR)pshi->Handle[entry_idx].ObjectPointer<<std::dec<<std::endl;
#endif
						SuspendThread(gft_thread);
						TerminateThread(gft_thread, 1);
						CloseHandle(gft_thread);
						gft_thread=CreateThread(NULL, 0, ThreadGetFileType, (LPVOID)&thread_tuple, CREATE_SUSPENDED, NULL);
						SetThreadPriority(gft_thread, THREAD_PRIORITY_TIME_CRITICAL);
						ResumeThread(gft_thread);
						is_disk_file=false;
					}

					if (is_disk_file) {
						std::wstring fpath=FPRoutines::GetHandlePath(hDupFile, param_full);
#if DEBUG>=3
						if (fpath.length()) std::wcerr<<L"\t\""<<fpath<<L"\"";
#endif
						if (fpath.length()&&MultiWildcardCmp(arg_wcard, fpath.c_str(), param_strict?MWC_PTH:MWC_STR)) {
							ul_array.push_back(prc_pid);
							//Close handle to cached process so not to check it's handles again
							CloseHandle(hProcess);
							hProcess=NULL;
#if DEBUG>=3
							std::wcerr<<L" - MATCHED";
#endif
						}
#if DEBUG>=3
						if (fpath.length()) std::wcerr<<std::endl;
#endif
					}
					CloseHandle(hDupFile);
				}
			}
			if (hProcess) CloseHandle(hProcess);
			hDupFile=INVALID_HANDLE_VALUE;
			SetEvent(get_type_event);
			CloseHandle(gft_thread);
			CloseHandle(get_type_event);
			CloseHandle(ready_event);			
		}
		
		if (h_ownexe!=INVALID_HANDLE_VALUE) CloseHandle(h_ownexe);
	}
	
	PrintCommonKillPrefix();
	std::wcout<<L"having opened files that match ";
	PrintCommonWildcardInfix(arg_wcard);
	
	bool found=!ul_array.empty()&&ApplyToProcesses([this, &ul_array](ULONG_PTR PID, const std::wstring &name, const std::wstring &path, bool applied){
		if (std::find(ul_array.begin(), ul_array.end(), PID)!=ul_array.end()) {
			if (!applied) std::wcout<<L"\" FOUND:"<<std::endl;
			KillProcess(PID, name, path);
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

DWORD WINAPI Killers::ThreadGetFileType(LPVOID lpParameter)
{
	HANDLE get_type_event=std::get<0>(*(OflTuple*)lpParameter);
	HANDLE ready_event=std::get<1>(*(OflTuple*)lpParameter);
	HANDLE *test_handle=std::get<2>(*(OflTuple*)lpParameter);
	bool *is_disk_file=std::get<3>(*(OflTuple*)lpParameter);

	while (WaitForSingleObject(get_type_event, INFINITE)==WAIT_OBJECT_0) {
		if (*test_handle==INVALID_HANDLE_VALUE) break;
		
		if (GetFileType(*test_handle)==FILE_TYPE_DISK)
			*is_disk_file=true;
		else
			*is_disk_file=false;

		SetEvent(ready_event);
	}
	
	return 0;
}
