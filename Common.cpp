#include "Hout.h"
#include "Common.h"
#include <algorithm>
#include <iostream>

#define SNK_VERSION L"v2.1"

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

bool MultiWildcardCmp(const wchar_t* wild, const wchar_t* string, const wchar_t* delim, bool is_path) 
{
	wchar_t buffer[wcslen(wild)+1];
	wcscpy(buffer, wild);
	
	for (wchar_t* token=wcstok(buffer, delim); token; token=wcstok(NULL, delim))
		if (is_path?PathWildcardCmp(token, string):WildcardCmp(token, string)) return true;
	
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

bool PidListCmp(const wchar_t* pid_list, std::vector<ULONG_PTR> *uptr_array, const ULONG_PTR *pid) 
{
	std::vector<ULONG_PTR> local_uptr_array;
	
	if (!uptr_array)
		uptr_array=&local_uptr_array;
	
	if (pid_list) {
		wchar_t buffer[wcslen(pid_list)+1];
		wcscpy(buffer, pid_list);
		
		ULONG_PTR dw_pri, dw_sec, *pdw_cur=&dw_pri;
		wchar_t* rtok;
		bool cnv_err=false;
		
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
						for (DWORD dw_i=dw_pri; uptr_array->push_back(dw_i), dw_i!=dw_sec; dw_pri<=dw_sec?dw_i++:dw_i--);
						pdw_cur=&dw_pri;
					} else
						uptr_array->push_back(dw_pri);
					break;
				}
			}
			if (cnv_err) {
				std::wcerr<<L"Warning: PID list \""<<pid_list<<L"\" is malformed, error in token \""<<token<<L"\"!"<<std::endl;
				uptr_array->clear();
				return false;
			}
		}
		
		//All this hassle with sorting, erasing and following binary_search is to speed up performance with big PID arrays
		//Because intended use for this function is mass PID killing or killing single PIDs from vaguely known range
		std::sort(uptr_array->begin(), uptr_array->end());
		uptr_array->erase(std::unique(uptr_array->begin(), uptr_array->end()), uptr_array->end());
	}
	
	if (pid)
		return std::binary_search(uptr_array->begin(), uptr_array->end(), *pid);
	else
		return true;
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
	//Instead of using clumsy _wsplitpath use std::wstring magick nowing that supplied path is full one
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
	//It needs it because it is hevaily used in scenarios where real path should be reconstructed from some nonsense
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
	Hout::Separator(L"/sec", 2);
	Hout::Paragraph(L"Secured execution. Will exit program if there is another instance already running that has executed this switch.",
					4);
	Hout::Separator(L"/blk(:clear|[:full]=WCARDS)", 2);
	Hout::Paragraph(L"Add processes which name matches one of wildcars (case-insensitive, with globbing) to blacklist or clear blacklist.",
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
	Hout::Separator(L"/pid=PIDS", 2);
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
	Hout::Separator(L"/inr[:manual|:vista]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that doesn't respond (Is Not Responding).",
					4);
	Hout::Separator(L"/fsc[:anywnd][:primary]", 2);
	Hout::Paragraph(L"Kill process with highest cpu load that is running in fullscreen.",
					4);
	Hout::Separator(L"/fgd", 2);
	Hout::Paragraph(L"Kill process which window is in foreground.",
					4);
	Hout::EmptyLine();
	Hout::Separator(L"Settings:");
	Hout::Separator(L"+t|-t", 2);
	Hout::Paragraph(L"Will turn test mode on/off.",
					4);
	Hout::Separator(L"+v|-v", 2);
	Hout::Paragraph(L"Will turn verbose mode on/off.",
					4);
	Hout::Separator(L"+a|-a", 2);
	Hout::Paragraph(L" Will turn 'query all processes' mode on/off.",
					4);
	Hout::Separator(L"+l|-l", 2);
	Hout::Paragraph(L" Will turn 'loop' mode on/off.",
					4);
	Hout::Separator(L"+i|-i", 2);
	Hout::Paragraph(L" Will turn 'ignore' mode on/off.",
					4);
#else
	Hout::Separator(L"Usage: SnKh [settings_block|swith[:parametres][=argument]] ...");
	Hout::EmptyLine();
	Hout::Separator(L"Please check README.TXT for more information.");
#endif
}

void PrintVersion() 
{
#ifndef HIDDEN
#ifdef _WIN64
	Hout::Separator(L"Search and Kill (x64) " SNK_VERSION);
#else
	Hout::Separator(L"Search and Kill " SNK_VERSION);
#endif
	Hout::EmptyLine();
	Hout::Separator(L"Run with /hlp switch for usage information");
#else
#ifdef _WIN64
	Hout::Separator(L"Search and Kill (x64 windowless) " SNK_VERSION);
#else
	Hout::Separator(L"Search and Kill (windowless) " SNK_VERSION);
#endif
	Hout::EmptyLine();
	Hout::Separator(L"Please check README.TXT for more information");
#endif
	Hout::EmptyLine();
	Hout::Separator(L"Copyright (c) 2012-2016 Lcferrum");
	Hout::Separator(L"Licensed under BSD license - see LICENSE.TXT file for details");
}
