#include "Hout.h"
#include "Externs.h"
#include "Common.h"
#include "ConOut.h"
#include "Version.h"
#include <iostream>
#include <ntstatus.h>	//STATUS_INFO_LENGTH_MISMATCH

extern pNtQuerySystemInformation fnNtQuerySystemInformation;

//Original WildcardCmp: 
// Written by Jack Handy <jakkhandy@hotmail.com>
// http://www.codeproject.com/Articles/1088/Wildcard-string-compare-globbing
//Changes made:
// Uses wchar_t instead of char
// Match is case-insensitive
// Optimized cp variable increment
// "Path" version additionally matches '\' (Windows path delimiter) in string only with '\' in wildcard ignoring '?' and '*'
bool WildcardCmp(const wchar_t* wild, const wchar_t* string) 
{
	const wchar_t *cp=NULL, *mp=NULL;

	while ((*string)&&(*wild!=L'*')) {
		if ((towlower(*wild)!=towlower(*string))&&(*wild!=L'?'))
			return false;
		wild++;
		string++;
	}

	while (*string) {
		if (*wild==L'*') {
			if (!*++wild)
				return true;
			mp=wild;
			cp=string;
		} else if ((towlower(*wild)==towlower(*string))||(*wild==L'?')) {
			wild++;
			string++;
		} else {
			wild=mp;
			string=++cp;
		}
	}

	while (*wild==L'*')
		wild++;
	
	return !*wild;
}
bool PathWildcardCmp(const wchar_t* wild, const wchar_t* string) 
{
	const wchar_t *cp=NULL, *mp=NULL;
	
	while (*string&&*wild!=L'*') {
		if (towlower(*wild)!=towlower(*string)&&(*wild!=L'?'||*string==L'\\'))
			return false;
		wild++;
		string++;
	}
	
	while (*string) {
		if (*wild==L'*') {
			mp=++wild;
			cp=string;
		} else if (towlower(*wild)==towlower(*string)||(*wild==L'?'&&*string!=L'\\')) {
			wild++;
			string++;
		} else if (*cp==L'\\') {
			return false;
		} else {
			wild=mp;
			string=++cp;
		}
	}

	while (*wild==L'*')
		wild++;
	
	return !*wild;
}

bool SubstringCmp(const wchar_t* sub, const wchar_t* string) 
{
	const wchar_t* cur_sub;
	const wchar_t* cur_string;
	
	do {
		cur_sub=sub;
		cur_string=string;
		while (towlower(*cur_string)==towlower(*cur_sub)&&*cur_string!=L'\0') { cur_string++; cur_sub++; }
		if (*cur_sub==L'\0') return true;
	} while (*string++!=L'\0');

	return false;
}

bool MultiWildcardCmp(const wchar_t* wild, const wchar_t* string, MWCMode mode, const wchar_t* delim) 
{
	if (delim) {
		wchar_t buffer[wcslen(wild)+1];
		wcscpy(buffer, wild);
		for (wchar_t* token=wcstok(buffer, delim); token; token=wcstok(NULL, delim))
			switch (mode) {
				case MWC_PTH:
					if (PathWildcardCmp(token, string)) return true;
					break;
				case MWC_STR:
					if (WildcardCmp(token, string)) return true;
					break;
				case MWC_SUB:
					if (SubstringCmp(token, string)) return true;
					break;
			}
	} else {
		switch (mode) {
			case MWC_PTH:
				if (PathWildcardCmp(wild, string)) return true;
				break;
			case MWC_STR:
				if (WildcardCmp(wild, string)) return true;
				break;
			case MWC_SUB:
				if (SubstringCmp(wild, string)) return true;
				break;
		}
	}
	
	return false;
}

void MakeRulesFromArgv(int argc, wchar_t** argv, std::stack<std::wstring> &rules, int skip_argc)
{
	wchar_t *head, *token;
	while (argc-->skip_argc) switch (*argv[argc]) {
		case L'/':
			if ((token=wcschr(argv[argc], L'=')))
				*token++=L'\0';
		
			rules.push((head=wcstok(argv[argc], L":")));
			
			if (token)
				rules.push(std::wstring(L"=")+token);
			
			while ((token=wcstok(NULL, L":")))
				rules.push(head+std::wstring(L":")+token);
			
			continue;
		case L'+':
		case L'-':
			head=argv[argc];
		
			while (*++argv[argc]!=L'\0')
				rules.push({*head, *argv[argc]});
			
			continue;
		case L'#':
		case L'\0':
			continue;
		default:
			std::wcerr<<L"Warning: unknown input: "<<argv[argc]<<std::endl;
	}
	
#if DEBUG>=3
	std::stack<std::wstring> _rules=rules;
	std::wcerr<<L"" __FILE__ ":MakeRulesFromArgv:"<<__LINE__<<L": Rules (unfolding stack)..."<<std::endl;
	while (!_rules.empty()) {
		std::wcerr<<L"\t\t"<<_rules.top()<<std::endl;
		_rules.pop();
	}
#endif
}

HANDLE OpenProcessWrapper(DWORD dwProcessId, DWORD &dwDesiredAccess, DWORD dwMandatory) 
{
	//If OpenProcess with provided dwDesiredAccess succeeded - return resulting hProcess
	if (HANDLE hProcess=OpenProcess(dwDesiredAccess, FALSE, dwProcessId))
		return hProcess;
	
	//If PROCESS_ALL_ACCESS is required - fail
	if (dwDesiredAccess==PROCESS_ALL_ACCESS) {
		dwDesiredAccess=0;
		return NULL;
	//If dwDesiredAccess contains PROCESS_QUERY_INFORMATION - change it to PROCESS_QUERY_LIMITED_INFORMATION and try again
	} else if (dwDesiredAccess&PROCESS_QUERY_INFORMATION&~dwMandatory) {
		dwDesiredAccess&=~PROCESS_QUERY_INFORMATION;
		dwDesiredAccess|=PROCESS_QUERY_LIMITED_INFORMATION;
	//If dwDesiredAccess contains PROCESS_VM_READ - remove it and try again
	//Additionally change PROCESS_QUERY_LIMITED_INFORMATION to PROCESS_QUERY_INFORMATION if present
	} else if (dwDesiredAccess&PROCESS_VM_READ&~dwMandatory) {
		if (dwDesiredAccess&PROCESS_QUERY_LIMITED_INFORMATION&~dwMandatory) {
			dwDesiredAccess&=~PROCESS_QUERY_LIMITED_INFORMATION;
			dwDesiredAccess|=PROCESS_QUERY_INFORMATION;
		}
		dwDesiredAccess&=~PROCESS_VM_READ;
	//If no PROCESS_QUERY_INFORMATION or PROCESS_VM_READ flags was set - fail
	} else {
		dwDesiredAccess=0;
		return NULL;
	}
	
	return OpenProcessWrapper(dwProcessId, dwDesiredAccess, dwMandatory);
}

std::wstring GetNamePartFromFullPath(const std::wstring& fpath)
{
	//Instead of using clumsy _wsplitpath use std::wstring magick knowing that supplied path is full one
	size_t last_backslash;
	if ((last_backslash=fpath.find_last_of(L'\\'))!=std::wstring::npos&&last_backslash<fpath.length())
		return fpath.substr(last_backslash+1);
	else
		return std::wstring();
}

bool CheckIfFileExists(const wchar_t* fpath) 
{
	if (!fpath||fpath[0]==L'\0'||(				//We don't need NULL or empty paths
		(fpath[0]!=L'\\'||fpath[1]!=L'\\')&&	//We interested in UNC and...
		(fpath[1]!=L':'||fpath[2]!=L'\\')		//...absolute paths
		))
		return false;
	//Ballad about full vs relative paths
	//CheckIfFileExists needs full path: i.e. path which can't be misinterpreted - it should stay the same regardless of CWD, CD or PATH variable
	//It needs it because it is heavily used in scenarios where real path should be reconstructed from some nonsense
	//And some of this nonsense may look like relative path and be falsely reported as something that might be real
	//In the end, there is no relative-path based algorithms in SnK - only name and full-path based
	//Here MS have an official paper about which paths are considred relative/full on Windows: https://msdn.microsoft.com/library/windows/desktop/aa365247.aspx#paths
	//They also have PathIsRelative funcion in shlwapi.dll (4.71+)
	//In ReactOS/Wine PathIsRelative is reversed to the following algorithm (original Win NT algorithm is actually the same):
	//If it starts from slash ('\') or second character is colon (':') then return false, otherwise return true
	//Main thing to consider is Microsoft's definition of "relative path" - here it means "path relative to current directory of the current drive" (historically each drive letter has it's own current directory)
	//So if PathIsRelative returns false it doesn't really mean that path is absolute - it simply means that path doesn't satisfy the above-mentioned definition
	//E.g. "C:tmp.txt" (relative to current directory but not drive) and "\blah\blah.txt" (relative to current drive but not directory) causes PathIsRelative to return false
	//So here is refined algorithm for CheckIfFileExists to check if file path is absolute in strict NT kernel terms: RtlPathTypeUncAbsolute or RtlPathTypeDriveAbsolute (see RtlDetermineDosPathNameType_U):
	//It starts from double slash ("\\") or it's second-to-third chracters are colon with slash (":\") - it's assumed that supplied path has nothing to do with device paths
	
	DWORD dwAttrib=GetFileAttributes(fpath);	//Works with UNC paths (ok), relative paths (fixed by code above), affected by Wow64FsRedirection (need some external code to turn this off), can fail because of security restrictions (whatever)
	if (dwAttrib!=INVALID_FILE_ATTRIBUTES&&!(dwAttrib&FILE_ATTRIBUTE_DIRECTORY))	//Don't need directories
		return true;
	else
		return false;
}

LPVOID GetTokenInformationWrapper(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass)
{
	DWORD dwSize;
	LPVOID pti=NULL;
	if(!GetTokenInformation(TokenHandle, TokenInformationClass, NULL, 0, &dwSize)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER) {
		pti=(LPVOID)new BYTE[dwSize];
		if (!GetTokenInformation(TokenHandle, TokenInformationClass, pti, dwSize, &dwSize)) {
			delete[] (BYTE*)pti;
			pti=NULL;
		}
	}
	return pti;
}

bool IsTokenElevated(HANDLE hToken)
{
	bool elevated=false;

	TOKEN_ELEVATION elevation; 
	DWORD ret_len; 
	if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &ret_len))
		elevated=elevation.TokenIsElevated;
	
	return elevated;
}

bool IsTokenRestrictedEx(HANDLE hToken)
{
	//CreateRestrictedToken function can restrict a token by disabling SIDs, deleting privileges, and specifying a list of restricting SIDs
	//IsTokenRestricted function checks only for the list of restricting SIDs and is available only since Win 2k
	//IsTokenRestrictedEx also checks if token has any mandatory groups disabled, which is possible only with CreateRestrictedToken
	
	bool restricted=false;
	PTOKEN_GROUPS ptg;
	
	if ((ptg=(PTOKEN_GROUPS)GetTokenInformationWrapper(hToken, TokenRestrictedSids))) {
		restricted=ptg->GroupCount;
		delete[] (BYTE*)ptg;
	}
	
	if (!restricted&&(ptg=(PTOKEN_GROUPS)GetTokenInformationWrapper(hToken, TokenGroups))) {
		for (int i=0; i<ptg->GroupCount; i++)
		if ((ptg->Groups[i].Attributes&SE_GROUP_MANDATORY)&&!(ptg->Groups[i].Attributes&SE_GROUP_ENABLED)) {
			restricted=true;
			break;
		}
		delete[] (BYTE*)ptg;
	}
	
	return restricted;
}

namespace Win32Wcostream {
	Win32WcostreamBuf wcout_win32(Win32WcostreamBuf::WCOUT);
	Win32WcostreamBuf wcerr_win32(Win32WcostreamBuf::WCERR);
#ifdef HIDDEN
	std::wstring tee_buf;
#endif
}

void Win32WcostreamActivate()
{
#ifdef HIDDEN
	Win32Wcostream::wcout_win32.Activate(&Win32Wcostream::tee_buf);
#else
	Win32Wcostream::wcout_win32.Activate();
	CONSOLE_SCREEN_BUFFER_INFO csbi; 
	HANDLE hstdout;
	if ((hstdout=GetStdHandle(STD_OUTPUT_HANDLE))!=INVALID_HANDLE_VALUE)	//STD_OUTPUT_HANDLE - because Hout will output to std::wcout
		if (GetConsoleScreenBufferInfo(hstdout, &csbi))
			Hout::SetTerminalSize(csbi.dwSize.X);
#endif
	Win32Wcostream::wcerr_win32.Activate();
}

void Win32WcostreamDeactivate()
{
	Win32Wcostream::wcout_win32.Deactivate();
	Win32Wcostream::wcerr_win32.Deactivate();
}

void Win32WcostreamEnabled(bool state)
{
	Win32Wcostream::wcout_win32.OutputEnabled(state);
	Win32Wcostream::wcerr_win32.OutputEnabled(state);
}

#ifdef HIDDEN
bool Win32WcostreamMessageBox(bool ok_cancel)
{
	//MessageBox is not only made foregroung and topmost, but also steals focus through AttachThreadInput hack
	std::wcout.flush();
	DWORD fg_tid=GetWindowThreadProcessId(GetForegroundWindow(), NULL);
	AttachThreadInput(fg_tid, GetCurrentThreadId(), TRUE);
	UINT mb_type=MB_ICONWARNING|MB_SETFOREGROUND|MB_TOPMOST|MB_SYSTEMMODAL;
	if (ok_cancel) mb_type|=MB_OKCANCEL|MB_DEFBUTTON1;
		else mb_type|=MB_OK;
	bool ret=MessageBox(NULL, Win32Wcostream::tee_buf.c_str(), L"Search and Kill", mb_type)==IDOK;	//Actually MB_TOPMOST and MB_SETFOREGROUND are rudementary - it's MB_SYSTEMMODAL that sets window to foreground and makes it topmost
	AttachThreadInput(fg_tid, GetCurrentThreadId(), FALSE);
	Win32Wcostream::tee_buf.clear();
	return ret;
}
#endif


namespace CachedNtQuerySystemInformation {
	BYTE* spi_cache=NULL;
	DWORD spi_size=153600;	//150KB
	BYTE* shi_cache=NULL;
	DWORD shi_size=204800;	//200KB
	bool Wrapper(SYSTEM_INFORMATION_CLASS class_name, DWORD &class_size, BYTE* &class_cache, BYTE** class_buffer, bool clear_cache);
};

bool CachedNtQuerySystemInformation::Wrapper(SYSTEM_INFORMATION_CLASS class_name, DWORD &class_size, BYTE* &class_cache, BYTE** class_buffer, bool clear_cache)
{
	if (!fnNtQuerySystemInformation) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":CachedNtQuerySystemInformation::Wrapper:"<<__LINE__<<L": NtQuerySystemInformation not found!"<<std::endl;
#endif
		return false;
	}
	
	if (clear_cache) {
		delete[] class_cache;
		class_cache=NULL;
	} 
	
	if (!class_buffer) {
		return true;
	}
	
	if (class_cache) {
		*class_buffer=class_cache;
		return true;
	}

	//NtQuerySystemInformation before XP returns actual read size in ReturnLength rather than needed size
	//We can't tell for sure how many bytes will be needed to store system information and can be really large - like several hundred kilobytes
	DWORD ret_size=0, cur_size=class_size;
	NTSTATUS st;
	for (;;) {
		class_cache=new BYTE[cur_size];
		if ((st=fnNtQuerySystemInformation(class_name, class_cache, cur_size, &ret_size))!=STATUS_INFO_LENGTH_MISMATCH) break;
		delete[] class_cache;
		cur_size*=2;
	}
	
	if (NT_SUCCESS(st)&&ret_size) {
		*class_buffer=class_cache;
		class_size=ret_size+4096;	//+4KB in case of data increase in next uncached call so not to multiply buffer size
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":CachedNtQuerySystemInformation::Wrapper:"<<__LINE__<<L": NtQuerySystemInformation("<<class_name<<L").ReturnLength="<<ret_size<<std::endl;
#endif	
		return true;
	} else {
		delete[] class_cache;
		class_cache=NULL;
		return false;
	}
}

bool CachedNtQuerySystemProcessInformation(SYSTEM_PROCESS_INFORMATION** spi_buffer, bool clear_cache)
{
	return CachedNtQuerySystemInformation::Wrapper(SystemProcessInformation, CachedNtQuerySystemInformation::spi_size, CachedNtQuerySystemInformation::spi_cache, (BYTE**)spi_buffer, clear_cache);
}

bool CachedNtQuerySystemHandleInformation(SYSTEM_HANDLE_INFORMATION** shi_buffer, bool clear_cache)
{
	return CachedNtQuerySystemInformation::Wrapper(SystemHandleInformation, CachedNtQuerySystemInformation::shi_size, CachedNtQuerySystemInformation::shi_cache, (BYTE**)shi_buffer, clear_cache);
}

void PrintUsage() 
{
#ifndef HIDDEN
	Hout::Separator(L"Usage: SnK [settings_block|swith[:parametres][=argument]] ...");
	Hout::EmptyLine();
	Hout::Separator(L"This is a usage quick reference. Please check README.TXT for more information.");
	Hout::EmptyLine();
	Hout::Separator(L"Switches:");
	Hout::Separator(L"/hlp", 2);
	Hout::Paragraph(L"Print this help and exit.",
					4);
	Hout::Separator(L"/ver", 2);
	Hout::Paragraph(L"Print version information and exit.",
					4);
	Hout::Separator(L"/bpp", 2);
	Hout::Paragraph(L"Make standart Windows 'informational beep' and continue execution.",
					4);
	Hout::Separator(L"/prn=TEXT", 2);
	Hout::Paragraph(L"Print passed text to stdout and continue execution.",
					4);
	Hout::Separator(L"/sec", 2);
	Hout::Paragraph(L"Secured execution. Will exit program if there is another instance already running that has executed this switch.",
					4);
	Hout::Separator(L"/cpu", 2);
	Hout::Paragraph(L"Kill process with highest cpu load.",
					4);
	Hout::Separator(L"/pth[:full]=WCARDS", 2);
	Hout::Paragraph(L"Kill process with highest cpu load which name matches one of wildcars (case-insensitive, with globbing).",
					4);
	Hout::Separator(L"/mod[:full]=WCARDS", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that has module which name matches one of wildcars (case-insensitive, with globbing).",
					4);
	Hout::Separator(L"/pid[:parent|=PIDS]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load which PID belongs to PID array.",
					4);
	Hout::Separator(L"/d3d[:simple]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that uses DirectX (Direct3D).",
					4);
	Hout::Separator(L"/ogl[:simple]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that uses OpenGL.",
					4);
	Hout::Separator(L"/gld[:simple]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that uses Glide (3Dfx).",
					4);
	Hout::Separator(L"/inr[:plus]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that doesn't respond (Is Not Responding).",
					4);
	Hout::Separator(L"/fsc[:anywnd][:primary]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that is running in fullscreen.",
					4);
	Hout::Separator(L"/fgd[:anywnd]", 2);
	Hout::Paragraph(L"Kill process which window is in foreground.",
					4);
	Hout::Separator(L"/cmd[:sub][:utf8|:utf16]=FILE", 2);
	Hout::Paragraph(L"Load additional commands from file and continue execution.",
					4);
	Hout::Separator(L"/lst[:clrmask|:invmask]", 2);
	Hout::Paragraph(L"List currently available processes and continue execution.",
					4);
	Hout::Separator(L"/psh=ARGUMENT", 2);
	Hout::Paragraph(L"Push argument to argument stack and continue execution.",
					4);
	Hout::Separator(L"/pop[=ENV_VAR]", 2);
	Hout::Paragraph(L"Pop argument from argument stack and continue execution.",
					4);
	Hout::Separator(L"/end", 2);
	Hout::Paragraph(L"Unconditionally exit program.",
					4);
	Hout::EmptyLine();
	Hout::Separator(L"Settings:");
	Hout::Separator(L"+t|-t", 2);
	Hout::Paragraph(L"Turn 'test' mode on/off.",
					4);
	Hout::Separator(L"+v|-v", 2);
	Hout::Paragraph(L"Turn 'verbose' mode on/off.",
					4);
	Hout::Separator(L"+a|-a", 2);
	Hout::Paragraph(L"Turn 'query all processes' mode on/off.",
					4);
	Hout::Separator(L"+l|-l", 2);
	Hout::Paragraph(L"Turn 'loop' mode on/off.",
					4);
	Hout::Separator(L"+i|-i", 2);
	Hout::Paragraph(L"Turn 'ignore' mode on/off.",
					4);
	Hout::Separator(L"+n|-n", 2);
	Hout::Paragraph(L"Turn 'negate' mode on/off.",
					4);
	Hout::Separator(L"+b|-b", 2);
	Hout::Paragraph(L"Turn 'blacklist' mode on/off.",
					4);
	Hout::Separator(L"+w|-w", 2);
	Hout::Paragraph(L"Turn 'whitelist' mode on/off.",
					4);
	Hout::Separator(L"+r|-r", 2);
	Hout::Paragraph(L"Turn 'recently created sort' mode on/off.",
					4);
	Hout::Separator(L"+m|-m", 2);
	Hout::Paragraph(L"Turn 'mute' mode on/off.",
					4);
	Hout::Separator(L"+c|-c", 2);
	Hout::Paragraph(L"Turn 'close' mode on/off.",
					4);
	Hout::Separator(L"+e|-e", 2);
	Hout::Paragraph(L"Turn 'expand environment variables' mode on/off.",
					4);
#else
	Hout::Separator(L"Usage: SnKh [settings_block|swith[:parametres][=argument]] ...");
	Hout::EmptyLine();
	Hout::Separator(L"Please check README.TXT for more information.");
	Hout::EmptyLine();
#endif
}

void PrintVersion() 
{
#ifndef HIDDEN
#ifdef _WIN64
	Hout::Separator(L"Search and Kill (x64) v" SNK_STR_VERSION);
#else
	Hout::Separator(L"Search and Kill v" SNK_STR_VERSION);
#endif
#else
#ifdef _WIN64
	Hout::Separator(L"Search and Kill (x64 windowless) v" SNK_STR_VERSION);
#else
	Hout::Separator(L"Search and Kill (windowless) v" SNK_STR_VERSION);
#endif
#endif
	Hout::Separator(L"Built on " __DATE__ L" at " __TIME__);
	Hout::Separator(L"Copyright (c) " SNK_CRIGHT_YEARS " Lcferrum");
	Hout::Separator(L"Licensed under BSD license - see LICENSE.TXT file for details");
	Hout::EmptyLine();
#ifndef HIDDEN
	Hout::Separator(L"Run with /hlp switch for usage information");
#else
	Hout::Separator(L"Please check README.TXT for more information");
	Hout::EmptyLine();
#endif
}
