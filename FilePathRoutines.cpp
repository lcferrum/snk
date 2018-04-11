#include "FilePathRoutines.h"
#include "Common.h"
#include "Externs.h"
#include <map>
#include <cstddef>		//offsetof
#include <stdexcept>	//out_of_range
#include <ntstatus.h>	//STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_INFO_CLASS, STATUS_BUFFER_OVERFLOW, STATUS_INSUFFICIENT_RESOURCES
//NewAPIs.h is Micorosoft's SDK compatibility layer used to implemennt GetLongPathName functionality for Windows NT and 95
//SDK implementation uses OLE interfaces on NT/95 and Kernel32's own GetLongPathName on everything else
//In SDK's implementation GetFileAttributes is called before actual OLE code to check if file in question exists
//On Windows NT pre-SP5 GetFileAttributes may return wrong value (report that file exists when it's actually not) - see KB193763
//Though it shoudn't be a problem because future OLE code will fail anyway - the only concern being system error code not being set porperly
#define COMPILE_NEWAPIS_STUBS
#define WANT_GETLONGPATHNAME_WRAPPER
#include <newapis.h>	//Probe_GetLongPathName

#ifdef DEBUG
#include <iostream>
#endif

//Version of PROCESS_BASIC_INFORMATION with x86_64 align
typedef struct _PROCESS_BASIC_INFORMATION64 {
	NTSTATUS ExitStatus;
	PTR_64(PPEB) PebBaseAddress;
	PTR_64(KAFFINITY) AffinityMask;
	KPRIORITY BasePriority;
	PTR_64(ULONG_PTR) UniqueProcessId;
	PTR_64(ULONG_PTR) InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

//Version of UNICODE_STRING with x86 align
typedef struct _UNICODE_STRING32 {
	USHORT Length;		
	USHORT MaximumLength;
	PTR_32(PWSTR) Buffer;
} UNICODE_STRING32;

//Version of UNICODE_STRING with x86_64 align
typedef struct _UNICODE_STRING64 {
	USHORT Length;		
	USHORT MaximumLength;
	PTR_64(PWSTR) Buffer;
} UNICODE_STRING64;

//Version of CURDIR with x86 align
typedef struct _CURDIR32 {
	UNICODE_STRING32 DosPath;
	PTR_32(HANDLE) Handle;
} CURDIR32;

//Version of CURDIR with x86_64 align
typedef struct _CURDIR64 {
	UNICODE_STRING64 DosPath;
	PTR_64(HANDLE) Handle;
} CURDIR64;

//Cut-down version of RTL_USER_PROCESS_PARAMETERS with x86 align
typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
	BYTE Reserved[36];
	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	PTR_32(PVOID) Environment;
} RTL_USER_PROCESS_PARAMETERS32;

//Cut-down version of RTL_USER_PROCESS_PARAMETERS with x86_64 align
typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
	BYTE Reserved[56];
	CURDIR64 CurrentDirectory;
	UNICODE_STRING64 DllPath;
	UNICODE_STRING64 ImagePathName;
	UNICODE_STRING64 CommandLine;
	PTR_64(PVOID) Environment;
} RTL_USER_PROCESS_PARAMETERS64;

//Cut-down Vista version of RTL_USER_PROCESS_PARAMETERS with x86 align
typedef struct _RTL_USER_PROCESS_PARAMETERS32_VISTA {
	BYTE Reserved[656];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS32_VISTA;

//Cut-down Vista version of RTL_USER_PROCESS_PARAMETERS with x86_64 align
typedef struct _RTL_USER_PROCESS_PARAMETERS64_VISTA {
	BYTE Reserved[1008];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS64_VISTA;

//Cut-down version of PEB_LDR_DATA with x86 align
typedef struct _PEB_LDR_DATA32 {
	BYTE Reserved[12];
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32;

//Cut-down version of PEB_LDR_DATA with x86_64 align
typedef struct _PEB_LDR_DATA64 {
	BYTE Reserved[16];
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
} PEB_LDR_DATA64;

//Cut-down version of LDR_DATA_TABLE_ENTRY (aka LDR_MODULE) with x86 align
typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	PTR_32(PVOID) DllBase;
	PTR_32(PVOID) EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32;

//Cut-down version of LDR_DATA_TABLE_ENTRY (aka LDR_MODULE) with x86_64 align
typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	PTR_64(PVOID) DllBase;
	PTR_64(PVOID) EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
} LDR_DATA_TABLE_ENTRY64;

//Cut-down version of PEB with x86 align
typedef struct _PEB32 {
	BYTE Reserved[8];
	PTR_32(PVOID) ImageBaseAddress;
	PTR_32(PPEB_LDR_DATA) LdrData;
	PTR_32(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
} PEB32;

//Cut-down version of PEB with x86_64 align
typedef struct _PEB64 {
	BYTE Reserved[16];
	PTR_64(PVOID) ImageBaseAddress;
	PTR_64(PPEB_LDR_DATA) LdrData;
	PTR_64(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
} PEB64;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

//Not using native RTL_USER_PROCESS_PARAMETERS, MEMORY_BASIC_INFORMATION, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY and PEB structures so to be sure in offset consistency
#ifdef _WIN64
	typedef RTL_USER_PROCESS_PARAMETERS64 RTL_USER_PROCESS_PARAMETERSXX;
	typedef RTL_USER_PROCESS_PARAMETERS64_VISTA RTL_USER_PROCESS_PARAMETERSXX_VISTA;
	typedef CURDIR64 CURDIRXX;
	typedef PEB_LDR_DATA64 PEB_LDR_DATAXX;
	typedef LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRYXX;
	typedef PEB64 PEBXX;
#else
	typedef RTL_USER_PROCESS_PARAMETERS32 RTL_USER_PROCESS_PARAMETERSXX;
	typedef RTL_USER_PROCESS_PARAMETERS32_VISTA RTL_USER_PROCESS_PARAMETERSXX_VISTA;
	typedef CURDIR32 CURDIRXX;
	typedef PEB_LDR_DATA32 PEB_LDR_DATAXX;
	typedef LDR_DATA_TABLE_ENTRY32 LDR_DATA_TABLE_ENTRYXX;
	typedef PEB32 PEBXX;
#endif

#define SYMBOLIC_LINK_QUERY 0x0001

#define SystemProcessIdInformation (SYSTEM_INFORMATION_CLASS)0x58

extern pNtOpenSymbolicLinkObject fnNtOpenSymbolicLinkObject;
extern pNtQuerySymbolicLinkObject fnNtQuerySymbolicLinkObject;
extern pNtCreateFile fnNtCreateFile;
extern pNtQueryInformationFile fnNtQueryInformationFile;
extern pNtQueryObject fnNtQueryObject;
extern pNtQueryInformationProcess fnNtQueryInformationProcess;
extern pNtWow64QueryInformationProcess64 fnNtWow64QueryInformationProcess64;
extern pNtWow64ReadVirtualMemory64 fnNtWow64ReadVirtualMemory64;
extern pIsWow64Process fnIsWow64Process;
extern pNtQuerySystemInformation fnNtQuerySystemInformation;
extern pNtQueryVirtualMemory fnNtQueryVirtualMemory;
extern pNtWow64QueryVirtualMemory64 fnNtWow64QueryVirtualMemory64;

namespace FPRoutines {
	std::vector<std::pair<std::wstring, wchar_t>> DriveList;
	std::map<DWORD, std::wstring> ServiceMap;
	bool emulatedGetLongPathName=!GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetLongPathNameW");
	bool KernelToWin32Path(const wchar_t* krn_fpath, std::wstring &w32_fpath);
	bool GetMappedFileNameWrapper(HANDLE hProcess, LPVOID hMod, std::wstring &fpath);
	bool GetMappedFileNameWow64Wrapper(HANDLE hProcess, PTR_64(PVOID) hMod, std::wstring &fpath);
	bool CommandLineToApplicationName(wchar_t *cmdline, std::wstring &appname);
	void OwnPathCanonicalize(wchar_t* lpszBuf, const wchar_t* lpszPath);
	bool OwnPathIsUNCServerShare(const wchar_t* lpszPath);
	bool GetFP_ProcessImageFileNameWin32(HANDLE hProcess, std::wstring &fpath);
	bool GetFP_QueryServiceConfig(HANDLE PID, std::wstring &fpath);
	bool GetFP_PEB(HANDLE hProcess, std::wstring &fpath);
	bool GetFP_SystemProcessIdInformation(HANDLE PID, std::wstring &fpath);
	bool GetFP_ProcessImageFileName(HANDLE hProcess, std::wstring &fpath);
	std::wstring GetLongPathNameWrapper(const wchar_t* path);
	bool MaxPathAwareGetLongPathNameWrapper(std::wstring &fpath, bool *is_dir=NULL);
	bool CheckIfFileExists(const wchar_t* fpath, bool req_abs=false);
}

void FPRoutines::FillDriveList() 
{
	DriveList.clear();
	
	if (!fnNtOpenSymbolicLinkObject) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":FillDriveMap:"<<__LINE__<<L": NtOpenSymbolicLinkObject not found!"<<std::endl;
#endif
		return;
	}
	
	if (!fnNtQuerySymbolicLinkObject) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":FillDriveMap:"<<__LINE__<<L": NtQuerySymbolicLinkObject not found!"<<std::endl;
#endif
		return;
	}
	
	if (!fnNtCreateFile) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":FillDriveMap:"<<__LINE__<<L": NtCreateFile not found!"<<std::endl;
#endif
		return;
	}
	
	if (!fnNtQueryObject) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":FillDriveMap:"<<__LINE__<<L": NtQueryObject not found!"<<std::endl;
#endif
		return;
	}
	
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttribs;	
	wchar_t drive_lnk[]=L"\\??\\A:";
	UNICODE_STRING u_drive_lnk={(USHORT)(sizeof(drive_lnk)-sizeof(wchar_t)), (USHORT)sizeof(drive_lnk), drive_lnk};
	IO_STATUS_BLOCK ioStatusBlock;
	BYTE oni_buf[1024];
	
	//InitializeObjectAttributes is a macros that assigns OBJECT_ATTRIBUTES it's parameters
	//Second parameter is assigned to OBJECT_ATTRIBUTES.ObjectName
	//OBJECT_ATTRIBUTES.ObjectName is a UNICODE_STRING which Buffer member is just a pointer to actual buffer (drive_lnk)
	//That's why changing buffer contents won't require calling InitializeObjectAttributes second time
	InitializeObjectAttributes(&objAttribs, &u_drive_lnk, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//There are several ways to enumerate all drives and get their NT paths
	//QueryDosDevice does the job but doesn't display paths for drive letters that are mapped network drives
	//NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject is better approach because it resolves mapped network drives letters
	//But it has drawback - mapped network drives letters often resolve to NT path that contains some internal IDs making it difficult to use it NT->Win32 path conversion
	//Example of such path: "\Device\LanmanRedirector\;Z:00000000000894aa\PC_NAME\SHARE_NAME"
	//And at last we have NtCreateFile(FILE_DIRECTORY_FILE)/NtQueryObject approach
	//It works even better than NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject - mapped drives are resolved to ordinary NT paths
	//With previous example it will now look like this: "\Device\LanmanRedirector\PC_NAME\SHARE_NAME"
	//Though there are two caveats:
	//	1) Don't append drive with backslash or NtCreateFile will open root directory instead (imagine it's floppy drive without disk inserted)
	//	2) Under NT4 NtQueryObject will fail with every drive letter except real mapped network drives (though ObjectNameInformation still gets filled with proper path)
	//Also, when mapped network drive being queried - code won't force system to check whether drive in offline or not
	//This means code won't stop there to wait for system response, which is good
	//The only time when there is really delay in execution is when system is in the process of changing drive status (e.g. explorer trying to access no longer available network drive)
	//Only in this case when trying to open such drive code will wait for system to update drive status
	//So we keep NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject as backup approach in case we are on NT4 (this approach still works there)
	for (drive_lnk[4]=L'A'; drive_lnk[4]<=L'Z'; drive_lnk[4]++)	{	//4'th index is a drive letter
		if (NT_SUCCESS(fnNtCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objAttribs, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0))) {
			if (NT_SUCCESS(fnNtQueryObject(hFile, ObjectNameInformation, (OBJECT_NAME_INFORMATION*)oni_buf, 1024, NULL))) {
				//Actually OBJECT_NAME_INFORMATION contains NULL-terminated UNICODE_STRING but we can save std::wstring constructor time and provide it with string length
				DriveList.push_back(std::make_pair(std::wstring(((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Buffer, ((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Length/sizeof(wchar_t)), drive_lnk[4]));
				CloseHandle(hFile);
				continue;
			}
			CloseHandle(hFile);
		}
		
		if (NT_SUCCESS(fnNtOpenSymbolicLinkObject(&hFile, SYMBOLIC_LINK_QUERY, &objAttribs))) {
			//In buf_len function returns not the actual buffer size needed for UNICODE_STRING, but the size of the UNICODE_STRING.Buffer itself
			//And this UNICODE_STRING should be already initialized before the second call - buffer created, Buffer pointer and MaximumLength set
			//Returned UNICODE_STRING includes terminating NULL
			UNICODE_STRING u_path={};
			DWORD buf_len;
			if (fnNtQuerySymbolicLinkObject(hFile, &u_path, &buf_len)==STATUS_BUFFER_TOO_SMALL) {
				u_path.Buffer=(wchar_t*)new BYTE[buf_len];	//buf_len is Length + terminating NULL
				u_path.MaximumLength=buf_len;
				if (NT_SUCCESS(fnNtQuerySymbolicLinkObject(hFile, &u_path, &buf_len))) {
					//As was said earlier returned UNICODE_STRING is NULL-terminated but we can save std::wstring constructor time and provide it with string length
					DriveList.push_back(std::make_pair(std::wstring(u_path.Buffer, u_path.Length/sizeof(wchar_t)), drive_lnk[4]));
				}
				delete[] (BYTE*)u_path.Buffer;
			}
			
			CloseHandle(hFile);
		}
	}
}

//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::CheckIfFileExists(const wchar_t* fpath, bool req_abs) 
{
	if (req_abs) {
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
		
		if (!fpath||fpath[0]==L'\0'||(				//We don't need NULL or empty paths
			(fpath[0]!=L'\\'||fpath[1]!=L'\\')&&	//We interested in UNC and...
			(fpath[1]!=L':'||fpath[2]!=L'\\')		//...absolute paths
			)) return false;
	}
	
	DWORD dwAttrib=GetFileAttributes(fpath);	//Works with UNC paths (ok), relative paths (fixed by code above), affected by Wow64FsRedirection (need some external code to turn this off), can fail because of security restrictions (whatever)
	if (dwAttrib!=INVALID_FILE_ATTRIBUTES&&!(dwAttrib&FILE_ATTRIBUTE_DIRECTORY))	//Don't need directories
		return true;
	else
		return false;
}

//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::CommandLineToApplicationName(wchar_t *cmdline, std::wstring &appname)
{
	//Same algorithm as CreateProcess uses to get application name from command line
	//This also searches in current working directory, so it's better to set it to something relevant beforehand
	//Though before everything else current image directory will be searched - and this is still a problem
	//Do not use NULL cmdline with this function - check it elsewhere
	
	wchar_t* linescan=cmdline;
	wchar_t* appnamestart;
	wchar_t savedchar;
	wchar_t retbuf[MAX_PATH];
	DWORD retlen;
	
	//First we check if we are lucky enough to have application name quoted
	if (*linescan==L'\"') {
		appnamestart=++linescan;
		while (*linescan!=L'\0'&&*linescan!=L'\"') linescan++;
	}
	
	//If it's the case we will go straight to checking validness of quoted path using Duff's Device ('cause gotos are evil, amirite?)
	//Otherwise, just stop at each whitespace and check whether or not we have valid application name
	//N.B. Using switch with bool generates warning (...oh wow) and casting it to int solves this (C++ guarantees that true is casted to 1 and false is casted to 0)
	switch ((int)(linescan==cmdline)) {
		case 1:
			appnamestart=linescan;
			for (;;) {
				//This loop actually means that we will stop at every whitespace even if they are consecutive
				//It's original CreateProcess behaviour
				while (*linescan!=L'\0'&&*linescan!=L' '&&*linescan!=L'\t') linescan++;
		case 0:
				savedchar=*linescan;
				*linescan=L'\0';
				
				//Search resulting path using SearchPath, appending exe extension if needed
				//SearchPath always returns absolute paths
				//SearchPath will also do a nice thing and convert slashes to backslashes
				//N.B.:
				//CreateProcess still (at least on Win 10) has limitation that if application name is not supplied, module name portion of command line is limited to MAX_PATH
				//This limitation actually stems from the fact that CreateProcess calls SearchPath with MAX_PATH as buffer length when searching for module name within command line
				//We are doing exactly the same because there is no point here to be better than CreateProcess
				retlen=SearchPath(NULL, appnamestart, L".exe", MAX_PATH, retbuf, NULL);
				
				*linescan=savedchar;
				
				//If path is found and it's not a directory (CheckIfFileExists will make sure it is) - application name is found
				if (retlen&&retlen<MAX_PATH&&CheckIfFileExists(retbuf)) {
					appname=retbuf;
					return true;
				//If we came here from quoted path processing or reached the end of command line - fail miserably
				} else if (*linescan==L'\0'||*linescan==L'\"') {
					return false;
				//Otherwise - continue searching for whitespaces
				} else {
					linescan++;
				}
			}
	}
	
	return false; //Control flow should never reach here so placing it just to make Clang happy
}

//Based on PathCanonicalizeW from ReactOS:
// Path Functions [reactos/dll/win32/shlwapi/path.c]
// Copyright 1999, 2000 Juergen Schmied
// Copyright 2001, 2002 Jon Griffiths
// Licensed under GNU Lesser General Public License version 2.1
//PathCanonicalize from ReactOS differs in the following ways from various Win32 PathCanonicalize forms:
// From PathCanonicalize (available since shlwapi.dll v4.70):
//  - final and source path are not restricted to MAX_PATH length
//  - accepts paths with "\\" prefix (UNC non-long path prefix)
// From PathCchCanonicalize (available since Win 8):
//  - final path is not restricted to MAX_PATH length
//  - caller doesn't have to declare the size of the returned string
//  - doesn't accept paths with "\\?\" and "\\?\UNC\" prefixes (long path prefixes)
//  - doesn't follow rule "remove all trailing periods, except when preceded by the asterisk"
// From PathCchCanonicalizeEx (available since Win 8):
//  - caller doesn't have to declare the size of the returned string
//  - doesn't accept paths with "\\?\" and "\\?\UNC\" prefixes (long path prefixes)
//  - doesn't follow rule "remove all trailing periods, except when preceded by the asterisk"
//Because this function is internal to FPRoutines, it lacks sanity checks, commonly found in API functions, present in PathCanonicalizeW from ReactOS
//So don't use it when lpszBuf or lpszPath might be NULL
void FPRoutines::OwnPathCanonicalize(wchar_t* lpszBuf, const wchar_t* lpszPath)
{
	wchar_t* lpszDst=lpszBuf;
	const wchar_t* lpszSrc=lpszPath;

	*lpszDst=L'\0';

	if (!*lpszPath)	{
		*lpszBuf++=L'\\';
		*lpszBuf=L'\0';
		return;
	}

	//Copy path root
	if (*lpszSrc==L'\\') {
		//In case of "\"
		*lpszDst++=*lpszSrc++;
	} else if (*lpszSrc&&lpszSrc[1]==L':') {
		//In case of "X:\"
		*lpszDst++=*lpszSrc++;
		*lpszDst++=*lpszSrc++;
		if (*lpszSrc==L'\\') *lpszDst++=*lpszSrc++;
	}

	//Canonicalize the rest of the path
	while (*lpszSrc) {
		if (*lpszSrc==L'.') {
			if (lpszSrc[1]==L'\\'&&(lpszSrc==lpszPath||lpszSrc[-1]==L'\\'||lpszSrc[-1]==L':')) {
				//Skip ".\"
				lpszSrc+=2;
			} else if (lpszSrc[1]==L'.'&&(lpszDst==lpszBuf||lpszDst[-1]==L'\\')) {
				//"\.." backs up a directory, over the root if it has no "\" following "X:."
				//".." is ignored if it would remove a UNC server name or initial "\\"
				
				if (lpszDst!=lpszBuf) {
					//Allow PathIsUNCServerShare test on lpszBuf
					*lpszDst=L'\0';
					
					if (lpszDst>lpszBuf+1&&lpszDst[-1]==L'\\'&&(lpszDst[-2]!=L'\\'||lpszDst>lpszBuf+2)) {
						if (lpszDst[-2]==L':'&&(lpszDst>lpszBuf+3||lpszDst[-3]==L':')) {
							lpszDst-=2;
							
							while (lpszDst>lpszBuf&&*lpszDst!=L'\\') lpszDst--;
							
							if (*lpszDst==L'\\') 
								//Reset to last "\"
								lpszDst++;
							else
								//Start path again from new root
								lpszDst=lpszBuf;
						} else if (lpszDst[-2]!=L':'&&!OwnPathIsUNCServerShare(lpszBuf))
							lpszDst-=2;
					}
					
					while (lpszDst>lpszBuf&&*lpszDst!=L'\\') lpszDst--;
					
					if (lpszDst==lpszBuf) {
						*lpszDst++=L'\\';
						lpszSrc++;
					}
				}
				
				//Skip ".." in src path
				lpszSrc+=2;
			} else
				*lpszDst++=*lpszSrc++;
		} else
			*lpszDst++=*lpszSrc++;
	}
	
	//Append "\" to naked drive specs
	if (lpszDst-lpszBuf==2&&lpszDst[-1]==L':') *lpszDst++=L'\\';
	*lpszDst++=L'\0';
}

//Based on PathIsUNCServerShareW from ReactOS:
// Path Functions [reactos/dll/win32/shlwapi/path.c]
// Copyright 1999, 2000 Juergen Schmied
// Copyright 2001, 2002 Jon Griffiths
// Licensed under GNU Lesser General Public License version 2.1
//PathIsUNCServerShare from Win32 is available since shlwapi.dll v4.71
//Because this function is internal to FPRoutines, it lacks sanity checks, commonly found in API functions, present in PathIsUNCServerShareW from ReactOS
//So don't use it when lpszPath might be NULL
bool FPRoutines::OwnPathIsUNCServerShare(const wchar_t* lpszPath)
{
	if (*lpszPath++==L'\\'&&*lpszPath++==L'\\') {
		bool bSeenSlash=false;
		
		while (*lpszPath) {
			if (*lpszPath==L'\\') {
				if (bSeenSlash)
					return false;
				bSeenSlash=true;
			}

			lpszPath++;
		}
		
		return bSeenSlash;
	}

	return false;
}

//AFFECTED BY WOW64 REDIRECTION
void FPRoutines::FillServiceMap() 
{
	ServiceMap.clear();
	
	SC_HANDLE schSCMgr;
	SC_HANDLE schSvc;
	DWORD ret_len, svc_cnt=0;
	BOOL st;
	QUERY_SERVICE_CONFIG *pqsc;
	ENUM_SERVICE_STATUS_PROCESS *pessp=NULL;
	std::wstring abs_path;
	
	if (!(schSCMgr=OpenSCManager(NULL, NULL, STANDARD_RIGHTS_READ|SC_MANAGER_ENUMERATE_SERVICE)))	 // Simple read and enumerate rights are enough
		return;
		
	if (!(st=EnumServicesStatusEx(schSCMgr, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &ret_len, &svc_cnt, NULL, NULL))&&(GetLastError()==ERROR_MORE_DATA)) {
		pessp=(ENUM_SERVICE_STATUS_PROCESS*)new BYTE[ret_len];
		st=EnumServicesStatusEx(schSCMgr, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (BYTE*)pessp, ret_len, &ret_len, &svc_cnt, NULL, NULL);
	}
	
	if (st) {	
		//We change CWD to Windows system directory like we are Service Control Manager so CommandLineToApplicationName will work properly
		wchar_t* orig_cwd=NULL;
		wchar_t win_dir[MAX_PATH];
		DWORD buflen=GetSystemDirectory(win_dir, MAX_PATH);
		if (buflen&&buflen<MAX_PATH&&(buflen=GetCurrentDirectory(0, NULL))) {
			orig_cwd=new wchar_t[buflen];
			GetCurrentDirectory(buflen, orig_cwd);
			SetCurrentDirectory(win_dir);
		}
		
		wchar_t exe_path[MAX_PATH];
		wchar_t* lst_bslash;
		buflen=GetModuleFileName(NULL, exe_path, MAX_PATH);
		//GetModuleFileName always returns module's full path (not some relative-to-something-path even if it was passed to CreateProcess in first place)
		//So instead of using _wsplitpath/_makepath or PathRemoveFileSpec, which have additional code to deal with relative paths, just use wcsrchr to find last backslash occurrence
		if (buflen&&buflen<MAX_PATH&&(lst_bslash=wcsrchr(exe_path, L'\\')))
			*++lst_bslash=L'\0';
		else
			*exe_path=L'\0';
		
		for (int iSvc=0; iSvc<svc_cnt; iSvc++) 
		//Check if ServiceMap already contains needed record
		//PID 0 is Task Scheduler and we are not interested in it
		if (pessp[iSvc].ServiceStatusProcess.dwProcessId&&(ServiceMap.find(pessp[iSvc].ServiceStatusProcess.dwProcessId)==ServiceMap.end())) {
			//If failed to open service - just continue quering other services				
			if (!(schSvc=OpenService(schSCMgr, pessp[iSvc].lpServiceName, SERVICE_QUERY_CONFIG)))
				continue;
			
			pqsc=NULL;
			
			if (!(st=QueryServiceConfig(schSvc, NULL, 0, &ret_len))&&(GetLastError()==ERROR_INSUFFICIENT_BUFFER)) {
				pqsc=(QUERY_SERVICE_CONFIG*)new BYTE[ret_len];
				st=QueryServiceConfig(schSvc, pqsc, ret_len, &ret_len);
			}
			
			//lpBinaryPathName is an expanded HKLM\SYSTEM\CurrentControlSet\services\*\ImagePath key passed as lpCommandLine to CreateProcess function (lpApplicationName is NULL)
			//It means that it is a command line of some kind, with a first argument not necessary being fully qualified path, and we should parse it accordingly
			//CommandLineToApplicationName implements set of parsing rules for CreateProcess' lpCommandLine as described in https://msdn.microsoft.com/library/windows/desktop/ms682425.aspx
			//After calling CommandLineToApplicationName we use sanity check to find if found service path is somewhere within current image directory
			//This is done because SearchPath, used in CommandLineToApplicationName, has a bad habit of searching in current image directory before everything else
			//So service paths that reside in current image directory are treated as false positive
			//N.B.: 
			//Historically backslash IS the path separator used in Windows, and it was done so to distinguish path separator from DOS command line option specifier
			//E.g. in CMD (and it works only here) you can actually omit whitespase if option specifier is slash: "C:\dir\some_program /option" is the same as "C:\dir\some_program/option"
			//Some Win32 API calls and OS components actually work with both slash and backslash, though it's more like undocumented feature
			//And CreateProcess is among them
			//So CommandLineToApplicationName is also made to work with slashes
			if (st&&pqsc&&pqsc->lpBinaryPathName) {
#if DEBUG>=3
				std::wcerr<<L"" __FILE__ ":FillServiceMap:"<<__LINE__<<L": Quering service \""<<pessp[iSvc].lpServiceName<<L"\" ("<<pessp[iSvc].ServiceStatusProcess.dwProcessId<<L") ImagePath=\""<<pqsc->lpBinaryPathName<<L"\""<<std::endl;
#endif
				if (CommandLineToApplicationName(pqsc->lpBinaryPathName, abs_path)&&_wcsnicmp(abs_path.c_str(), exe_path, wcslen(exe_path))) {
#if DEBUG>=3
					std::wcerr<<L"" __FILE__ ":FillServiceMap:"<<__LINE__<<L": Found path for service \""<<pessp[iSvc].lpServiceName<<L"\" ("<<pessp[iSvc].ServiceStatusProcess.dwProcessId<<L"): \""<<abs_path<<L"\""<<std::endl;
#endif
					ServiceMap[pessp[iSvc].ServiceStatusProcess.dwProcessId]=std::move(abs_path);
				}
				
				//N.B.:
				//Q103000 from MSDN (https://support.microsoft.com/en-us/kb/103000) mentions that for services ImagePath key defaults to "SystemRoot\SYSTEM32\ServiceName.EXE"
				//Where ServiceName is service's key name and SystemRoot is corresponding environment variable
				//In reality ScStartService function from Service Control Manager (SCM) requires ImagePath key to be present and doesn't have default value for it
				//So services with empty or absent ImagePath key just fail to start
			}
			
			delete[] (BYTE*)pqsc;
			CloseServiceHandle(schSvc);
		}
		
		if (orig_cwd) {
			SetCurrentDirectory(orig_cwd);
			delete[] orig_cwd;
		}
	}
		
	delete[] (BYTE*)pessp;
	CloseServiceHandle(schSCMgr);
}

bool FPRoutines::GetMappedFileNameWrapper(HANDLE hProcess, LPVOID hMod, std::wstring &fpath)
{
	//Alright, this is reinvention of GetMappedFileName from psapi.dll
	//But we have several reasons for this
	//NT4 not necessarry includes this DLL out-of-the-box - official MS installation disks don't have one as none of SPs
	//It should be installed as redistributable package that shipped separately (psinst.exe) or as part of "Windows NT 4.0 Resource Kit" or "Windows NT 4.0 SDK"
	//Though most modern non-MS "all-inclusive" NT4 install disks usually install it by default
	//On Win 9x we have no psapi.dll though some "unofficial" SPs for 9x systems install it anyway
	//In the end exporting it dynamically may succeed on Win 9x if such SP was installed but using it will result in crash
	//So here we re-implementing NT's GetMappedFileName so not to be dependent on psapi.dll
	
	if (!fnNtQueryVirtualMemory) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetMappedFileNameWrapper:"<<__LINE__<<L": NtQueryVirtualMemory not found!"<<std::endl;
#endif
		return false;
	}
	
	//Actual string buffer size is MAX_PATH characters - same size is used in MS's GetMappedFileName implementation
	//In MS's implementation returned UNICODE_STRING.Length is incremented by one to get needed buffer size w/ NULL instead of just getting UNICODE_STRING.MaximumLength directly
	//And then NULL is set separetly in new buffer after copying UNICODE_STRING.Length amount of data
	//NtQueryVirtualMemory just fails if buffer is not enough - it doesn't return truncated data
	
	SIZE_T buf_len=sizeof(UNICODE_STRING)+MAX_PATH*sizeof(wchar_t);
	SIZE_T ret_len;
	BYTE msn_buf[buf_len+sizeof(wchar_t)];	//+1 wchar_t for forced NULL terminator 
	
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION and PROCESS_VM_READ
	if (NT_SUCCESS(fnNtQueryVirtualMemory(hProcess, hMod, MemorySectionName, msn_buf, buf_len, &ret_len))) {
		//Conforming to MS implementation we don't rely on returned buffer to be NULL terminated 
		((UNICODE_STRING*)msn_buf)->Buffer[((UNICODE_STRING*)msn_buf)->Length/sizeof(wchar_t)]=L'\0';
		return KernelToWin32Path(((UNICODE_STRING*)msn_buf)->Buffer, fpath);
	}
	
	return false;
}

bool FPRoutines::GetMappedFileNameWow64Wrapper(HANDLE hProcess, PTR_64(PVOID) hMod, std::wstring &fpath)
{
	//See comments on GetMappedFileNameWrapper - this is it's WoW64 equivalent
	
	if (!fnNtWow64QueryVirtualMemory64) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetMappedFileNameWow64Wrapper:"<<__LINE__<<L": NtWow64QueryVirtualMemory64 not found!"<<std::endl;
#endif
		return false;
	}

#if DEBUG>=2	
	std::wcerr<<L"" __FILE__ ":GetMappedFileNameWow64Wrapper:"<<__LINE__<<L": not implemented!"<<std::endl;
#endif
	
	//NtWow64QueryVirtualMemory64 existed on WoW64 only till Win 10 - from Win XP x64 to Win 8.1
	//And while it existed it supported only one MEMORY_INFORMATION_CLASS - MemoryBasicInformation
	//Everything else returns STATUS_NOT_IMPLEMENTED
		
	return false;
}

//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::KernelToWin32Path(const wchar_t* krn_fpath, std::wstring &w32_fpath)
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":KernelToWin32Path:"<<__LINE__<<L": Converting \""<<krn_fpath<<L"\"..."<<std::endl;
#endif

	//Check if Kernel path is already Win32
	if (CheckIfFileExists(krn_fpath)) {
		w32_fpath=krn_fpath;
		return true;
	}
	
	if (!fnNtCreateFile) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":KernelToWin32Path:"<<__LINE__<<L": NtCreateFile not found!"<<std::endl;
#endif
		return false;
	}

	if (!fnNtQueryInformationFile) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":KernelToWin32Path:"<<__LINE__<<L": NtQueryInformationFile not found!"<<std::endl;
#endif
		return false;
	}

	if (!fnNtQueryObject) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":KernelToWin32Path:"<<__LINE__<<L": NtQueryObject not found!"<<std::endl;
#endif
		return false;
	}
	
	//Basic algorithm is the following:
	//We have NT kernel path like "\Device\HarddiskVolume2\Windows\System32\wininit.exe" and should turn it to "user-readable" Win32 path
	//First, we should resolve any symbolic links in the path like "\SystemRoot" and "\??"
	//It could be done by opening the file (NtCreateFile) and then getting path to the handle (NtQueryObject(ObjectNameInformation))
	//Then, we try to match resulting path with one of the device prefixes from DriveList - this way we resolve device name to it's Win32 equivalent
	//If we have a match - swap device prefix with it's drive letter and we are good to go
	//If no match, usually that means it's some kind of network path which hasn't been mapped to any of drives
	//That's why we extract relative (to device prefix) path using NtQueryInformationFile(FileNameInformation) and make UNC path from it
	//Check if guess was right by testing resulting UNC path for existence

	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttribs;	
	UNICODE_STRING ustr_fpath={(USHORT)(wcslen(krn_fpath)*sizeof(wchar_t)), (USHORT)((wcslen(krn_fpath)+1)*sizeof(wchar_t)), const_cast<wchar_t*>(krn_fpath)};
	IO_STATUS_BLOCK ioStatusBlock;
	
	InitializeObjectAttributes(&objAttribs, &ustr_fpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//NtCreateFile will accept only NT kernel paths
	//NtCreateFile will not accept ordinary Win32 paths (will fail with STATUS_OBJECT_PATH_SYNTAX_BAD)
	if (!NT_SUCCESS(fnNtCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objAttribs, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0)))
		return false;
	
	//Very inconsistent function which behaviour differs between OS versions
	//Starting from Vista things are easy - just pass NULL buffer and zero length and you'll get STATUS_INFO_LENGTH_MISMATCH and needed buffer size
	//Before Vista things are ugly - you will get all kinds of error statuses because of insufficient buffer
	//And function won't necessary return needed buffer size - it actually depends on passed buffer size!
	//But worst of all is NT4 where function will never return needed buffer size and you can get real buffer overflow with some buffer sizes
	//So enumerating buffer sizes here is dangerous because of potential buffer overflow and all the unexpected nasty things that could occur afterwards
	//Internally, when calling NtQueryObject, Windows doesn't try to find actual buffer size - it just supplies some large buffer (like entire page!) and hopes for the best
	//We'll try something similar here: we already have kernel path, only portion of which may expand to something bigger
	//So let's assume that [current path length in bytes + 1024] is a sane buffer size (1024 - most common buffer size that Windows passes to NtQueryObject)
	//Returned path is NULL-terminated (MaximumLength is Length plus NULL-terminator, all in bytes)
	DWORD buf_len=ustr_fpath.Length+1024;
	BYTE oni_buf[buf_len];
	if (!NT_SUCCESS(fnNtQueryObject(hFile, ObjectNameInformation, (OBJECT_NAME_INFORMATION*)oni_buf, buf_len, NULL))) {
		CloseHandle(hFile);
		return false;
	}

	wchar_t* res_krn_path=((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Buffer;
	for (std::pair<std::wstring, wchar_t> &drive: DriveList) {
		if (!wcsncmp(drive.first.c_str(), res_krn_path, drive.first.length())&&(drive.first.back()==L'\\'||res_krn_path[drive.first.length()]==L'\\')) {
			CloseHandle(hFile);
			if (drive.first.back()==L'\\')
				w32_fpath={drive.second, L':', L'\\'};
			else
				w32_fpath={drive.second, L':'};
			w32_fpath.append(res_krn_path+drive.first.length());
			return true;
		}
	}

	//In contrast with NtQueryObject, NtQueryInformationFile is pretty predictable
	//To get needed buffer size just supply buffer that holds FILE_NAME_INFORMATION structure and wait for STATUS_BUFFER_OVERFLOW (in this case it's just a status, don't worry)
	//Needed buffer size (minus sizeof(FILE_NAME_INFORMATION)) will be in FILE_NAME_INFORMATION.FileNameLength
	//But we are already know sufficient buffer size from the call to NtQueryObject - no need to second guess here
	//NtQueryInformationFile(FileNameInformation) returns path relative to device
	//Returned path is not NULL-terminated (FileNameLength is string length in bytes)
	buf_len=((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Length+sizeof(FILE_NAME_INFORMATION);
	BYTE fni_buf[buf_len];
	if (!NT_SUCCESS(fnNtQueryInformationFile(hFile, &ioStatusBlock, (FILE_NAME_INFORMATION*)fni_buf, buf_len, FileNameInformation))) {
		CloseHandle(hFile);
		return false;
	}	
	
	CloseHandle(hFile);
	std::wstring unc_path{L'\\'};
	unc_path.append(((FILE_NAME_INFORMATION*)fni_buf)->FileName, ((FILE_NAME_INFORMATION*)fni_buf)->FileNameLength/sizeof(wchar_t));
	if (CheckIfFileExists(unc_path.c_str())) {
		w32_fpath=std::move(unc_path);
		return true;
	}

	return false;
}

//WoW64 redirection removed:            YES
//Clears navigational elements:         YES
//Maintains backslashes:                YES
//Restores letter case:                 YES
//Resolves 8.3 paths:                   YES
//Produces only Win32 paths:            YES
//Supports long paths:                  YES (shortens names)
bool FPRoutines::GetFP_ProcessImageFileNameWin32(HANDLE hProcess, std::wstring &fpath) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileNameWin32:"<<__LINE__<<L": Calling..."<<std::endl;
#endif

	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileNameWin32:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return false;
	}
	
	NTSTATUS st;
	DWORD buf_len;
	
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	//This call works only on Vista and above and gets Win32 path
	//Returned buf_len doesn't include terminating NULL character, but we don't need to add NULL terminator because PUNICODE_STRING will be assigned using wstring.assign() 
	if ((st=fnNtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &buf_len))==STATUS_INFO_LENGTH_MISMATCH) {
		BYTE ustr_fpath[buf_len];
		if (NT_SUCCESS(fnNtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, ustr_fpath, buf_len, NULL))) {
			fpath.assign(((PUNICODE_STRING)ustr_fpath)->Buffer, ((PUNICODE_STRING)ustr_fpath)->Length/sizeof(wchar_t));
			return true;
		}
	} else {
#if DEBUG>=2
		if (st==STATUS_INVALID_INFO_CLASS)
			std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileNameWin32:"<<__LINE__<<L": NtQueryInformationProcess(ProcessImageFileNameWin32) failed - information class not supported!"<<std::endl;
#endif
	}

	return false;
}

//WoW64 redirection removed:            YES (services always launched natively)
//Clears navigational elements:         YES
//Maintains backslashes:                NO
//Restores letter case:                 NO
//Resolves 8.3 paths:                   NO
//Produces only Win32 paths:            YES (binPath supports only Win32 paths)
//Supports long paths:                  YES (returns whatever was in binPath)
bool FPRoutines::GetFP_QueryServiceConfig(HANDLE PID, std::wstring &fpath) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFP_QueryServiceConfig:"<<__LINE__<<L": Calling..."<<std::endl;
#endif

	std::map<DWORD, std::wstring>::iterator it;
	if ((it=ServiceMap.find((ULONG_PTR)PID))!=ServiceMap.end()) {
		fpath=it->second;
		return true;
	} else {
		return false;
	}
}

//WoW64 redirection removed:            YES
//Clears navigational elements:         NO
//Maintains backslashes:                YES
//Restores letter case:                 NO
//Resolves 8.3 paths:                   NO
//Produces only Win32 paths:            NO (returns whatever was in PEB w/o KernelToWin32Path)
//Supports long paths:                  YES (returns whatever was in PEB)
//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::GetFP_PEB(HANDLE hProcess, std::wstring &fpath) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": Calling..."<<std::endl;
#endif
	
	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return false;
	}

	PROCESS_BASIC_INFORMATION proc_info={};
	NTSTATUS st;
	ULONG_PTR PebBaseAddress32=0;
	PROCESS_BASIC_INFORMATION64 proc_info64={};
	//By default it's assumed that target PID and current process are not WOW64 processes, i.e. run natively
	BOOL pid_wow64=FALSE;
	BOOL cur_wow64=FALSE;

	//In case when IsWow64Process is available - check whether target PID and current process is WoW64
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if (fnIsWow64Process) {
		//If IsWow64Process is available and returns false - it's an actual error and we should fail
		if (!fnIsWow64Process(hProcess, &pid_wow64)||!fnIsWow64Process(GetCurrentProcess(), &cur_wow64))
			return false;
	}
	
	//UNICODE_STRING in RTL_USER_PROCESS_PARAMETERS usually includes terminating NULL character in it's buffer
	//But in case of kernel paths, maximum buffer size can be theoretically overrun so it's safer to assume that adding terminating character is our responsibility
	if (pid_wow64==cur_wow64) {
		//Bitness of current process and target process is the same - it's safe to use native ReadProcessMemory with native structures
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc_info, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(st)||!proc_info.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtQueryInformationProcess(ProcessBasicInformation) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
		
		PVOID pRUPP;
		//Requires PROCESS_VM_READ	
		if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)proc_info.PebBaseAddress+offsetof(PEBXX, ProcessParameters)), &pRUPP, sizeof(pRUPP), NULL)) {
			UNICODE_STRING ImagePathName;
			if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)pRUPP+offsetof(RTL_USER_PROCESS_PARAMETERSXX, ImagePathName)), &ImagePathName, sizeof(ImagePathName), NULL)) {
				wchar_t buffer[ImagePathName.MaximumLength/sizeof(wchar_t)+1];
				buffer[ImagePathName.Length/sizeof(wchar_t)]=L'\0';
				if (ReadProcessMemory(hProcess, ImagePathName.Buffer, &buffer, ImagePathName.MaximumLength, NULL))
					//Filepath is found, but it can be in kernel form
					return KernelToWin32Path(buffer, fpath);
			}
		}
	} else {
#ifdef _WIN64	//_WIN64 ***********************************
		//Reading 32-bit process from 64-bit process
		
		//Some kind of undocumented behaviour:
		//Documentation states that ProcessWow64Information returns WoW64 flag for selected process
		//But actually this flag contains WoW64 process' PEB address
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessWow64Information, &PebBaseAddress32, sizeof(PebBaseAddress32), NULL);
		if (!NT_SUCCESS(st)||!PebBaseAddress32) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtQueryInformationProcess(ProcessWow64Information) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
		
		PTR_32(PVOID) pRUPP32;
		//Requires PROCESS_VM_READ
		//PebBaseAddress32, pRUPP32 and ImagePathName32.Buffer pointers are already casted to integers
		if (ReadProcessMemory(hProcess, (LPCVOID)(PebBaseAddress32+offsetof(PEB32, ProcessParameters)), &pRUPP32, sizeof(pRUPP32), NULL)) {
			UNICODE_STRING32 ImagePathName32;
			if (ReadProcessMemory(hProcess, (LPCVOID)(pRUPP32+offsetof(RTL_USER_PROCESS_PARAMETERS32, ImagePathName)), &ImagePathName32, sizeof(ImagePathName32), NULL)) {
				wchar_t buffer[ImagePathName32.MaximumLength/sizeof(wchar_t)+1];
				buffer[ImagePathName32.Length/sizeof(wchar_t)]=L'\0';
				if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)ImagePathName32.Buffer, &buffer, ImagePathName32.MaximumLength, NULL))
					//Filepath is found, but it can be in kernel form
					return KernelToWin32Path(buffer, fpath);
			}
		}
#else	//_WIN64 ***********************************
		//Reading 64-bit process from 32-bit process
	
		if (!fnNtWow64QueryInformationProcess64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtWow64QueryInformationProcess64 not found!"<<std::endl;
#endif
			return false;
		}
		
		if (!fnNtWow64ReadVirtualMemory64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtWow64ReadVirtualMemory64 not found!"<<std::endl;
#endif
			return false;
		}
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &proc_info64, sizeof(PROCESS_BASIC_INFORMATION64), NULL);
		if (!NT_SUCCESS(st)||!proc_info64.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetFP_PEB:"<<__LINE__<<L": NtWow64QueryInformationProcess64(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
		
		PTR_64(PVOID) pRUPP64;
		//Requires PROCESS_VM_READ
		//proc_info64.PebBaseAddress, pRUPP64 and ImagePathName64.Buffer pointers are already casted to integers
		if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, proc_info64.PebBaseAddress+offsetof(PEB64, ProcessParameters), &pRUPP64, sizeof(pRUPP64), NULL))) {
			UNICODE_STRING64 ImagePathName64;
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, pRUPP64+offsetof(RTL_USER_PROCESS_PARAMETERS64, ImagePathName), &ImagePathName64, sizeof(ImagePathName64), NULL))) {
				wchar_t buffer[ImagePathName64.MaximumLength/sizeof(wchar_t)+1];
				buffer[ImagePathName64.Length/sizeof(wchar_t)]=L'\0';
				if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, ImagePathName64.Buffer, &buffer, ImagePathName64.MaximumLength, NULL)))
					//Filepath is found, but it can be in kernel form
					return KernelToWin32Path(buffer, fpath);
			}
		}
#endif	//_WIN64 ***********************************
	}
	
	return false;
}

//WoW64 redirection removed:            YES
//Clears navigational elements:         YES
//Maintains backslashes:                YES
//Restores letter case:                 YES
//Resolves 8.3 paths:                   YES
//Produces only Win32 paths:            NO (returns only kernel paths w/o KernelToWin32Path)
//Supports long paths:                  YES (shortens names)
//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::GetFP_SystemProcessIdInformation(HANDLE PID, std::wstring &fpath) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFP_SystemProcessIdInformation:"<<__LINE__<<L": Calling..."<<std::endl;
#endif
	
	if (!fnNtQuerySystemInformation) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetFP_SystemProcessIdInformation:"<<__LINE__<<L": NtQuerySystemInformation not found!"<<std::endl;
#endif
		return false;
	}
	
	NTSTATUS st;
	SYSTEM_PROCESS_ID_INFORMATION processIdInfo;
	processIdInfo.ProcessId=PID;
	processIdInfo.ImageName.Buffer=NULL;
	processIdInfo.ImageName.Length=0;
	processIdInfo.ImageName.MaximumLength=0;
	bool result=false;
	
	//On x86 OS NtQuerySystemInformation(SystemProcessIdInformation) doesn't return needed length in ImageName.MaximumLength
	//So we can't tell for sure how many bytes will be needed to store unicode string
	//On x64 ImageName.MaximumLength will contain needed buffer length on first call if supplied length is insufficient
	//MaximumLength length is actual Length plus terminating character, so when function succeed Buffer will already contain terminating NULL
	do {
		delete[] processIdInfo.ImageName.Buffer;
		processIdInfo.ImageName.Buffer=(wchar_t*)new BYTE[(processIdInfo.ImageName.MaximumLength+=1024)];  //each iteration buffer size is increased by 1 KB
	} while ((st=fnNtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(SYSTEM_PROCESS_ID_INFORMATION), NULL))==STATUS_INFO_LENGTH_MISMATCH);
	
	if (!NT_SUCCESS(st)) {
#if DEBUG>=2
		if (st==STATUS_INVALID_INFO_CLASS)
			std::wcerr<<L"" __FILE__ ":GetFP_SystemProcessIdInformation:"<<__LINE__<<L": NtQuerySystemInformation(SystemProcessIdInformation) failed - information class not supported!"<<std::endl;
#endif
	} else
		//Filepath is found, but we need to convert it to Win32 form
		result=KernelToWin32Path(processIdInfo.ImageName.Buffer, fpath);
	
	delete[] (BYTE*)processIdInfo.ImageName.Buffer;
	return result;
}

//WoW64 redirection removed:            YES
//Clears navigational elements:         YES
//Maintains backslashes:                YES
//Restores letter case:                 YES
//Resolves 8.3 paths:                   YES
//Produces only Win32 paths:            NO (returns only kernel paths w/o KernelToWin32Path)
//Supports long paths:                  YES (shortens names)
//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::GetFP_ProcessImageFileName(HANDLE hProcess, std::wstring &fpath) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileName:"<<__LINE__<<L": Calling..."<<std::endl;
#endif
	
	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileName:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return false;
	}
	
	NTSTATUS st;
	DWORD buf_len;
	
	//If function succeed, returned UNICODE_STRING.Buffer already contains terminating NULL character
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if ((st=fnNtQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &buf_len))==STATUS_INFO_LENGTH_MISMATCH) {
		BYTE ustr_fname[buf_len];
		if (NT_SUCCESS(fnNtQueryInformationProcess(hProcess, ProcessImageFileName, ustr_fname, buf_len, NULL))) {
			return KernelToWin32Path(((PUNICODE_STRING)ustr_fname)->Buffer, fpath);
		}
	} else {
#if DEBUG>=2
		if (st==STATUS_INVALID_INFO_CLASS)
			std::wcerr<<L"" __FILE__ ":GetFP_ProcessImageFileName:"<<__LINE__<<L": NtQueryInformationProcess(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
	}
	
	return false;
}

//AFFECTED BY WOW64 REDIRECTION
bool FPRoutines::MaxPathAwareGetLongPathNameWrapper(std::wstring &fpath, bool *is_dir)
{
	//GetLongPathName is MAX_PATH aware with "\\?\" but emulated GetLongPathName isn't
	
	if (emulatedGetLongPathName) {
		std::wstring lpath=GetLongPathNameWrapper(fpath.c_str());
		if (lpath.length()) {
			if (is_dir) *is_dir=GetFileAttributes(lpath.c_str())&FILE_ATTRIBUTE_DIRECTORY;
			fpath=std::move(lpath);
			return true;
		}
		return false;
	}
	
	wchar_t upath[fpath.length()+7]; //7 is "\?\UNC" w/ NULL-terminator
	bool is_unc=fpath.front()==L'\\';
	if (is_unc) {
		wcscpy(upath, L"\\\\?\\UNC");
		wcscat(upath, fpath.c_str()+1);
	} else {
		wcscpy(upath, L"\\\\?\\");
		wcscat(upath, fpath.c_str());
	}
	if (DWORD buf_len=Probe_GetLongPathName(upath, NULL, 0)) {
		wchar_t buffer[buf_len];
		if (Probe_GetLongPathName(upath, buffer, buf_len)) {
			if (is_dir) *is_dir=GetFileAttributes(upath)&FILE_ATTRIBUTE_DIRECTORY;
			//We now have valid (GetLongPathName fails if path doesn't exist - relative check) Win32 LFN file path
			//Removing "\\?\" prefix
			wchar_t* clean_buf=buffer+4;
			if (is_unc) *(clean_buf+=2)=L'\\';
			fpath=clean_buf;
			return true;
		}
	}
	return false;
}

//AFFECTED BY WOW64 REDIRECTION
std::wstring FPRoutines::GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Getting path for PID "<<(ULONG_PTR)PID<<L"..."<<std::endl;
#endif
	std::wstring fpath;
	
	if (
		(hProcess&&GetFP_ProcessImageFileNameWin32(hProcess, fpath))||	//First we use NtQueryInformationProcess(ProcessImageFileNameWin32) to get file path: assuming that SnK is run with admin rights and current OS is likely to be Vista or above (it's a method requirement), we will get Win32 path for every process
		GetFP_QueryServiceConfig(PID, fpath)||							//If previous method failed, now starts guessing work: we assume that method most likely failed because of obsolete OS (because, hey, you'd better grant SnK admin rights to do it work properly!) - this is a pretty good method to get Win32 filepath, it doesn't require any rights, works on everything from NT4, the only downside being that it can only query services
		(hProcess&&vm_read&&GetFP_PEB(hProcess, fpath))||				//One more method for obsolete OSes: obtaining file path from PEB is complex (and may require kernel to Win32 path conversion), needs more security rights than every other method, but works on everything from NT4 and doesn't have limited scope like previous method
		GetFP_SystemProcessIdInformation(PID, fpath)||					//Previous methods failed so it seems that actually we doesn't have enough security rights (because previous two methods will get file path even from NT4 if given admin rights): NtQuerySystemInformation(SystemProcessIdInformation) is a good choice if current process is limited in rights, because it doesn't require any, but have two downsides - it works only on Vista and above and kernel to Win32 path conversion is mandatory
		(hProcess&&GetFP_ProcessImageFileName(hProcess, fpath))			//It's a last chance: maybe we have a not-completely-obsolete OS (like XP) and security limitations prevent us from accessing PEB but permit something less complex - NtQueryInformationProcess(ProcessImageFileName) works starting from XP, requires same amount of rights as the very first method but kernel to Win32 path conversion is mandatory
		) {
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Normalizing path with GetLongPathName and PathCanonicalize: \""<<fpath<<L"\"..."<<std::endl;
#endif
		//There is a possibilty that returned path will include 8.3 portions (and be all-lowercase)
		//So it's better convert it to LFN with GetLongPathName (this also restores character case)
		//To get rid of navigation elements (like "." and ".."), that can be also be present in returned path, we use own version of PathCanonicalize
		//N.B.:
		//GetLongPathName accepts slash as path deparator but not with "\\?\"
		//Also GetLongPathName doesn't convert slashes to backslashes in returned path
		//But it's not of concern here because none of GetFP functions is able to return path with slashes as path separator
		//OwnPathCanonicalize can't fail but won't accept lon path prefixes like "\\?\"
		if (MaxPathAwareGetLongPathNameWrapper(fpath)) {
			wchar_t final_path[fpath.length()+2];	//OwnPathCanonicalize can theoretically add single backslash to the path
			OwnPathCanonicalize(final_path, fpath.c_str());
#if DEBUG>=3
			std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Found path for PID "<<(ULONG_PTR)PID<<L": \""<<final_path<<L"\""<<std::endl;
#endif
			return final_path;
		}
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": GetLongPathName failed for PID "<<(ULONG_PTR)PID<<std::endl;
#endif
	}
	
	return L"";
}

//AFFECTED BY WOW64 REDIRECTION
std::wstring FPRoutines::GetLongPathNameWrapper(const wchar_t* path)
{
	//GetLongPathName is UNC aware, affected by Wow64FsRedirection, may fail because of security restrictions

	if (DWORD buf_len=Probe_GetLongPathName(path, NULL, 0)) {
		wchar_t buffer[buf_len];
		if (Probe_GetLongPathName(path, buffer, buf_len)) {
			return buffer;
		}
	}
	return L"";
}

//WoW64 redirection removed:            NO (w/o GetMappedFileName)
//Clears navigational elements:         YES
//Maintains backslashes:                YES
//Restores letter case:                 NO (w/o GetLongPathName)
//Resolves 8.3 paths:                   NO (w/o GetLongPathName)
//Produces only Win32 paths:            YES (process image path, which can be in kernel form, is skipped)
//Supports long paths:                  ?
std::vector<std::wstring> FPRoutines::GetModuleList(HANDLE hProcess, bool full) 
{
	std::vector<std::wstring> mlist;
	
	if (!hProcess)
		return mlist;
	
	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return mlist;
	}

	PROCESS_BASIC_INFORMATION proc_info={};
	NTSTATUS st;
	ULONG_PTR PebBaseAddress32=0;
	PROCESS_BASIC_INFORMATION64 proc_info64={};
	//By default it's assumed that target PID and current process are not WOW64 processes, i.e. run natively
	BOOL pid_wow64=FALSE;
	BOOL cur_wow64=FALSE;

	//In case when IsWow64Process is available - check whether target PID and current process is WoW64
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if (fnIsWow64Process) {
		//If IsWow64Process is available and returns false - it's an actual error and we should fail
		if (!fnIsWow64Process(hProcess, &pid_wow64)||!fnIsWow64Process(GetCurrentProcess(), &cur_wow64))
			return mlist;
	}
	
	//UNICODE_STRING in LDR_DATA_TABLE_ENTRY usually includes terminating NULL character in it's buffer
	//Kernel paths are possible only in image path and they are skipped so it's pretty safe to use MaximumLength
	if (pid_wow64==cur_wow64) {
		//Bitness of current process and target process is the same - it's safe to use native ReadProcessMemory with native structures
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc_info, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(st)||!proc_info.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtQueryInformationProcess(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
			return mlist;
		}
		
		//Requires PROCESS_VM_READ	
		//All members of PEBXX and LDR_DATA_TABLE_ENTRYXX are already casted to integers
		PEBXX pebXX;
		if (ReadProcessMemory(hProcess, proc_info.PebBaseAddress, &pebXX, sizeof(pebXX), NULL)) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRYXX ldteXX;
			if (ReadProcessMemory(hProcess, (LPCVOID)(pebXX.LdrData+offsetof(PEB_LDR_DATAXX, InMemoryOrderModuleList)), &ldteXX.InMemoryOrderModuleList, sizeof(LIST_ENTRY), NULL)&&ldteXX.InMemoryOrderModuleList.Flink) {
				while (ldteXX.InMemoryOrderModuleList.Flink!=(pebXX.LdrData+offsetof(PEB_LDR_DATAXX, InMemoryOrderModuleList))) {	//Enumerate all the list members till list closes
					if (ReadProcessMemory(hProcess, (LPCVOID)(ldteXX.InMemoryOrderModuleList.Flink-offsetof(LDR_DATA_TABLE_ENTRYXX, InMemoryOrderModuleList)), &ldteXX, sizeof(ldteXX), NULL)) {
						if (ldteXX.DllBase==pebXX.ImageBaseAddress)	//Skip process image entry
							continue;
							
						//Module paths can include 8.3 portions so normalize it with GetLongPathName
						std::wstring norm_buf;
						if (pid_wow64) {
							//GetMappedFileNameWrapper is used here only to undo WoW64 redirection
							//So if target process is not WoW64 process - no need to call GetMappedFileNameWrapper for it
							if (GetMappedFileNameWrapper(hProcess, (LPVOID)ldteXX.DllBase, norm_buf))
								norm_buf=GetLongPathNameWrapper(norm_buf.c_str());
						} else {
							//Returned paths are all in Win32 form (except image path that is skipped)
							wchar_t name_buf[ldteXX.FullDllName.MaximumLength/sizeof(wchar_t)];						
							if (ReadProcessMemory(hProcess, (LPCVOID)ldteXX.FullDllName.Buffer, &name_buf, ldteXX.FullDllName.MaximumLength, NULL))
								norm_buf=GetLongPathNameWrapper(name_buf);
						}
						
						if (norm_buf.length()) {
							mlist.push_back(full?norm_buf:GetNamePartFromFullPath(norm_buf));
						} else if (!full) {
							//This is fallback option if we need just module name
							wchar_t name_buf[ldteXX.BaseDllName.MaximumLength/sizeof(wchar_t)];
							if (ReadProcessMemory(hProcess, (LPCVOID)ldteXX.BaseDllName.Buffer, &name_buf, ldteXX.BaseDllName.MaximumLength, NULL)) 
								mlist.push_back(name_buf);
						}
					} else
						break;
				}
			}
		}
	} else {
#ifdef _WIN64	//_WIN64 ***********************************
		//Reading 32-bit process from 64-bit process
		
		//Some kind of undocumented behaviour:
		//Documentation states that ProcessWow64Information returns WoW64 flag for selected process
		//But actually this flag contains WoW64 process' PEB address
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessWow64Information, &PebBaseAddress32, sizeof(PebBaseAddress32), NULL);
		if (!NT_SUCCESS(st)||!PebBaseAddress32) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtQueryInformationProcess(ProcessWow64Information) failed - information class not supported!"<<std::endl;
#endif
			return mlist;
		}
		
		//Requires PROCESS_VM_READ
		//PebBaseAddress32 and all members of PEB32 and LDR_DATA_TABLE_ENTRY32 are already casted to integers
		PEB32 peb32;
		if (ReadProcessMemory(hProcess, (LPCVOID)PebBaseAddress32, &peb32, sizeof(peb32), NULL)) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRY32 ldte32;
			if (ReadProcessMemory(hProcess, (LPCVOID)(peb32.LdrData+offsetof(PEB_LDR_DATA32, InMemoryOrderModuleList)), &ldte32.InMemoryOrderModuleList, sizeof(LIST_ENTRY), NULL)&&ldte32.InMemoryOrderModuleList.Flink) {
				while (ldte32.InMemoryOrderModuleList.Flink!=(peb32.LdrData+offsetof(PEB_LDR_DATA32, InMemoryOrderModuleList))) {	//Enumerate all the list members till list closes
					if (ReadProcessMemory(hProcess, (LPCVOID)(ldte32.InMemoryOrderModuleList.Flink-offsetof(LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList)), &ldte32, sizeof(ldte32), NULL)) {
						if (ldte32.DllBase==peb32.ImageBaseAddress)	//Skip process image entry
							continue;
						
						//If current ptocess is 64-bit, surely we are on x64 OS and 32-bit process is run under WoW64
						//We should use GetMappedFileNameWrapper to undo WoW64 redirection
						//Module paths can include 8.3 portions so normalize it with GetLongPathName
						std::wstring norm_buf;
						if (GetMappedFileNameWrapper(hProcess, (LPVOID)(ULONG_PTR)ldte32.DllBase, norm_buf))
							norm_buf=GetLongPathNameWrapper(norm_buf.c_str());
						
						if (norm_buf.length()) {
							mlist.push_back(full?norm_buf:GetNamePartFromFullPath(norm_buf));
						} else if (!full) {
							//This is fallback option if we need just module name
							wchar_t name_buf[ldte32.BaseDllName.MaximumLength/sizeof(wchar_t)];
							if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)ldte32.BaseDllName.Buffer, &name_buf, ldte32.BaseDllName.MaximumLength, NULL)) 
								mlist.push_back(name_buf);
						}
					} else
						break;
				}
			}
		}
#else	//_WIN64 ***********************************
		//Reading 64-bit process from 32-bit process
	
		if (!fnNtWow64QueryInformationProcess64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64QueryInformationProcess64 not found!"<<std::endl;
#endif
			return mlist;
		}
		
		if (!fnNtWow64ReadVirtualMemory64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64ReadVirtualMemory64 not found!"<<std::endl;
#endif
			return mlist;
		}
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &proc_info64, sizeof(PROCESS_BASIC_INFORMATION64), NULL);
		if (!NT_SUCCESS(st)||!proc_info64.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64QueryInformationProcess64(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
			return mlist;
		}
		
		//Requires PROCESS_VM_READ
		//proc_info64.PebBaseAddress and all members of PEB64 and LDR_DATA_TABLE_ENTRY64 are already casted to integers
		PEB64 peb64;
		if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, proc_info64.PebBaseAddress, &peb64, sizeof(peb64), NULL))) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRY64 ldte64;
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, peb64.LdrData+offsetof(PEB_LDR_DATA64, InMemoryOrderModuleList), &ldte64.InMemoryOrderModuleList, sizeof(LIST_ENTRY), NULL))&&ldte64.InMemoryOrderModuleList.Flink) {
				while (ldte64.InMemoryOrderModuleList.Flink!=(peb64.LdrData+offsetof(PEB_LDR_DATA64, InMemoryOrderModuleList))) {	//Enumerate all the list members till list closes
					if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, ldte64.InMemoryOrderModuleList.Flink-offsetof(LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList), &ldte64, sizeof(ldte64), NULL))) {
						if (ldte64.DllBase==peb64.ImageBaseAddress)	//Skip process image entry
							continue;
							
						//Not using GetMappedFileNameWow64Wrapper here
						//First of all - it's not implemented because of underlaying NtWow64QueryVirtualMemory64 not being properly implemented on WoW64
						//Actually, we can just use ordinary GetMappedFileNameWrapper, but it will work only with modules which DllBase's HIDWORD is NULL
						//Second - actually we don't need no GetMappedFileNameWow64Wrapper or GetMappedFileNameWrapper here
						//The whole point of getting module path from it's handle is in getting rid of WoW64 path redirection mechanism which affects BaseDllName/FullDllName
						//But we are queryng x64 process - it's simply doesn't run on WoW64 so has nothing to do with WoW64 redirection
							
						//Returned paths are all in Win32 form (except image path that is skipped)
						//Module paths can include 8.3 portions so normalize it with GetLongPathName
						std::wstring norm_buf;
						wchar_t name_buf[ldte64.FullDllName.MaximumLength/sizeof(wchar_t)];
						if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, ldte64.FullDllName.Buffer, &name_buf, ldte64.FullDllName.MaximumLength, NULL)))
							norm_buf=GetLongPathNameWrapper(name_buf);
						
						if (norm_buf.length()) {
							mlist.push_back(full?norm_buf:GetNamePartFromFullPath(norm_buf));
						} else if (!full) {
							//This is fallback option if we need just module name
							wchar_t name_buf[ldte64.BaseDllName.MaximumLength/sizeof(wchar_t)];
							if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, ldte64.BaseDllName.Buffer, &name_buf, ldte64.BaseDllName.MaximumLength, NULL))) 
								mlist.push_back(name_buf);
						}
					} else
						break;
				}
			}
		}
#endif	//_WIN64 ***********************************
	}
	
	return mlist;
}

//WoW64 redirection removed:            YES
//Clears navigational elements:         YES
//Maintains backslashes:                YES
//Restores letter case:                 YES
//Resolves 8.3 paths:                   NO (w/o GetLongPathName)
//Produces only Win32 paths:            YES (includes kernel to Win32 path conversion)
//Supports long paths:                  YES (keeps original path)
//AFFECTED BY WOW64 REDIRECTION
std::wstring FPRoutines::GetHandlePath(HANDLE hFile, bool full)
{
	if (!fnNtQueryInformationFile) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetHandlePath:"<<__LINE__<<L": NtQueryInformationFile not found!"<<std::endl;
#endif
		return L"";
	}
	
	if (!fnNtQueryObject) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetHandlePath:"<<__LINE__<<L": NtQueryObject not found!"<<std::endl;
#endif
		return L"";
	}
	
	//To get needed buffer size just supply buffer that holds FILE_NAME_INFORMATION structure and wait for STATUS_BUFFER_OVERFLOW
	//Needed buffer size (minus sizeof(FILE_NAME_INFORMATION)) will be in FILE_NAME_INFORMATION.FileNameLength
	//NtQueryInformationFile(FileNameInformation) returns path relative to device
	//Returned path is not NULL-terminated (FileNameLength is string length in bytes)
	//FileName member of FILE_NAME_INFORMATION is actually defined not as a pointer but as single char length buffer
	//If NtQueryInformationFile returned STATUS_SUCCESS then we have root directory
	//NtQueryInformationFile is not affected by WoW64 redirection
	FILE_NAME_INFORMATION fni_tmp;
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS nqif_status=fnNtQueryInformationFile(hFile, &ioStatusBlock, &fni_tmp, sizeof(FILE_NAME_INFORMATION), FileNameInformation);
	if (nqif_status==STATUS_BUFFER_OVERFLOW||nqif_status==STATUS_SUCCESS) {
		//See KernelToWin32Path for comments on NtQueryObject and general algorithm on getting Win32 path from file handle
		//NtQueryObject is not affected by WoW64 redirection
		DWORD buf_len=fni_tmp.FileNameLength+1024;
		BYTE oni_buf[buf_len];
		if (NT_SUCCESS(fnNtQueryObject(hFile, ObjectNameInformation, (OBJECT_NAME_INFORMATION*)oni_buf, buf_len, NULL))) {
			std::wstring hpath;
			wchar_t* res_krn_path=((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Buffer;
			
			for (std::pair<std::wstring, wchar_t> &drive: DriveList) {
				if (!wcsncmp(drive.first.c_str(), res_krn_path, drive.first.length())&&(drive.first.back()==L'\\'||res_krn_path[drive.first.length()]==L'\\')) {
					if (drive.first.back()==L'\\')
						hpath={drive.second, L':', L'\\'};
					else
						hpath={drive.second, L':'};
					hpath.append(res_krn_path+drive.first.length());
					break;
				}
			}
			
			if (hpath.empty()) {
				buf_len=fni_tmp.FileNameLength+sizeof(FILE_NAME_INFORMATION);
				BYTE fni_buf[buf_len];
				if (NT_SUCCESS(fnNtQueryInformationFile(hFile, &ioStatusBlock, (FILE_NAME_INFORMATION*)fni_buf, buf_len, FileNameInformation))) {
					hpath={L'\\'};
					hpath.append(((FILE_NAME_INFORMATION*)fni_buf)->FileName, ((FILE_NAME_INFORMATION*)fni_buf)->FileNameLength/sizeof(wchar_t));
				}
			}
			
			if (hpath.length()) {
				//There is a possibilty that returned path will include 8.3 portions
				//So it's better convert it to LFN with GetLongPathName
				//GetLongPathName fails for paths that don't exist
				bool is_dir;
				if (MaxPathAwareGetLongPathNameWrapper(hpath, &is_dir)) {
					if (full)
						return hpath;
					else if (!is_dir)
						return GetNamePartFromFullPath(hpath);
				}
			}
		}
	}

	return L"";
}

//WoW64 redirection removed:            N/A
//Clears navigational elements:         N/A
//Maintains backslashes:                N/A
//Restores letter case:                 N/A
//Resolves 8.3 paths:                   N/A
//Produces only Win32 paths:            N/A
//Supports long paths:                  N/A
//Returns actual copies of CommandLine, CurrentDirectory and Environment
bool FPRoutines::GetCmdCwdEnv(HANDLE hProcess, std::unique_ptr<wchar_t[]> &cmdline, std::unique_ptr<wchar_t[]> &cwdpath, std::unique_ptr<BYTE[]> &envblock)
{
	if (!hProcess)
		return false;
	
	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return false;
	}
	
	if (!fnNtQueryVirtualMemory) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtQueryVirtualMemory not found!"<<std::endl;
#endif
		return false;
	}

	
	PROCESS_BASIC_INFORMATION proc_info={};
	NTSTATUS st;
	ULONG_PTR PebBaseAddress32=0;
	PROCESS_BASIC_INFORMATION64 proc_info64={};
	//By default it's assumed that target PID and current process are not WOW64 processes, i.e. run natively
	BOOL pid_wow64=FALSE;
	BOOL cur_wow64=FALSE;

	//In case when IsWow64Process is available - check whether target PID and current process is WoW64
	//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
	if (fnIsWow64Process) {
		//If IsWow64Process is available and returns false - it's an actual error and we should fail
		if (!fnIsWow64Process(hProcess, &pid_wow64)||!fnIsWow64Process(GetCurrentProcess(), &cur_wow64))
			return false;
	}
	
	if (pid_wow64==cur_wow64) {
		//Bitness of current process and target process is the same - it's safe to use native ReadProcessMemory with native structures
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc_info, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(st)||!proc_info.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtQueryInformationProcess(ProcessBasicInformation) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
				
		PVOID pRUPP;
		//Requires PROCESS_VM_READ	
		if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)proc_info.PebBaseAddress+offsetof(PEBXX, ProcessParameters)), &pRUPP, sizeof(pRUPP), NULL)) {
			UNICODE_STRING CommandLine;
			CURDIRXX CurrentDirectory;
			ULONG_PTR Environment;
			MEMORY_BASIC_INFORMATION env_mbi;

			//GetCommandLine just returns RTL_USER_PROCESS_PARAMETER.CommandLine.Buffer
			if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)pRUPP+offsetof(RTL_USER_PROCESS_PARAMETERSXX, CommandLine)), &CommandLine, sizeof(CommandLine), NULL)) {
				cmdline.reset(new wchar_t[CommandLine.MaximumLength/sizeof(wchar_t)]);
				if (!ReadProcessMemory(hProcess, CommandLine.Buffer, cmdline.get(), CommandLine.MaximumLength, NULL)) return false;
			} else return false;
			
			//GetCurrentDirectory always terminates RTL_USER_PROCESS_PARAMETER.CurrentDirectory.DosPath.Buffer with NULL
			if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)pRUPP+offsetof(RTL_USER_PROCESS_PARAMETERSXX, CurrentDirectory)), &CurrentDirectory, sizeof(CurrentDirectory), NULL)) {
				cwdpath.reset(new wchar_t[CurrentDirectory.DosPath.Length/sizeof(wchar_t)+1]);
				cwdpath[CurrentDirectory.DosPath.Length/sizeof(wchar_t)]=L'\0';
				if (!ReadProcessMemory(hProcess, (LPCVOID)CurrentDirectory.DosPath.Buffer, cwdpath.get(), CurrentDirectory.DosPath.Length, NULL)) return false;
			} else return false;
			
			//RTL_USER_PROCESS_PARAMETER.Environment contains continous block of memory allocated with NtAllocateVirtualMemory
			if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)pRUPP+offsetof(RTL_USER_PROCESS_PARAMETERSXX, Environment)), &Environment, sizeof(Environment), NULL)&&
				NT_SUCCESS(fnNtQueryVirtualMemory(hProcess, (LPVOID)Environment, MemoryBasicInformation, &env_mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
				SIZE_T env_len=env_mbi.RegionSize-(Environment-(ULONG_PTR)env_mbi.BaseAddress);
				envblock.reset(new BYTE[env_len]);
				if (!ReadProcessMemory(hProcess, (LPCVOID)Environment, envblock.get(), env_len, NULL)) return false;
			} else return false;
			
			return true;
		}
	} else {
#ifdef _WIN64	//_WIN64 ***********************************
		//Reading 32-bit process from 64-bit process
		
		//Some kind of undocumented behaviour:
		//Documentation states that ProcessWow64Information returns WoW64 flag for selected process
		//But actually this flag contains WoW64 process' PEB address
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtQueryInformationProcess(hProcess, ProcessWow64Information, &PebBaseAddress32, sizeof(PebBaseAddress32), NULL);
		if (!NT_SUCCESS(st)||!PebBaseAddress32) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtQueryInformationProcess(ProcessWow64Information) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
		
		PTR_32(PVOID) pRUPP32;
		//Requires PROCESS_VM_READ
		//PebBaseAddress32, pRUPP32 and CommandLine32.Buffer pointers are already casted to integers
		if (ReadProcessMemory(hProcess, (LPCVOID)(PebBaseAddress32+offsetof(PEB32, ProcessParameters)), &pRUPP32, sizeof(pRUPP32), NULL)) {
			UNICODE_STRING32 CommandLine32;
			CURDIR32 CurrentDirectory32;
			PTR_32(PVOID) Environment32;
			MEMORY_BASIC_INFORMATION env_mbi;
			
			//GetCommandLine just returns RTL_USER_PROCESS_PARAMETER.CommandLine.Buffer
			if (ReadProcessMemory(hProcess, (LPCVOID)(pRUPP32+offsetof(RTL_USER_PROCESS_PARAMETERS32, CommandLine)), &CommandLine32, sizeof(CommandLine32), NULL)) {
				cmdline.reset(new wchar_t[CommandLine32.MaximumLength/sizeof(wchar_t)]);
				if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)CommandLine32.Buffer, cmdline.get(), CommandLine32.MaximumLength, NULL)) return false;
			} else return false;
			
			//GetCurrentDirectory always terminates RTL_USER_PROCESS_PARAMETER.CurrentDirectory.DosPath.Buffer with NULL
			if (ReadProcessMemory(hProcess, (LPCVOID)(pRUPP32+offsetof(RTL_USER_PROCESS_PARAMETERS32, CurrentDirectory)), &CurrentDirectory32, sizeof(CurrentDirectory32), NULL)) {
				cwdpath.reset(new wchar_t[CurrentDirectory32.DosPath.Length/sizeof(wchar_t)+1]);
				cwdpath[CurrentDirectory32.DosPath.Length/sizeof(wchar_t)]=L'\0';
				if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)CurrentDirectory32.DosPath.Buffer, cwdpath.get(), CurrentDirectory32.DosPath.Length, NULL)) return false;
			} else return false;
			
			//RTL_USER_PROCESS_PARAMETER.Environment contains continous block of memory allocated with NtAllocateVirtualMemory
			if (ReadProcessMemory(hProcess, (LPCVOID)(pRUPP32+offsetof(RTL_USER_PROCESS_PARAMETERS32, Environment)), &Environment32, sizeof(Environment32), NULL)&&
				NT_SUCCESS(fnNtQueryVirtualMemory(hProcess, (LPVOID)(ULONG_PTR)Environment32, MemoryBasicInformation, &env_mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
				SIZE_T env_len=env_mbi.RegionSize-(Environment32-(ULONG_PTR)env_mbi.BaseAddress);
				envblock.reset(new BYTE[env_len]);
				if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)Environment32, envblock.get(), env_len, NULL)) return false;
			} else return false;
			
			return true;
		}
#else	//_WIN64 ***********************************
		//Reading 64-bit process from 32-bit process
	
		if (!fnNtWow64QueryInformationProcess64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtWow64QueryInformationProcess64 not found!"<<std::endl;
#endif
			return false;
		}
		
		if (!fnNtWow64ReadVirtualMemory64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtWow64ReadVirtualMemory64 not found!"<<std::endl;
#endif
			return false;
		}

#if DEBUG>=2		
		if (!fnNtWow64QueryVirtualMemory64) {
			std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtWow64QueryVirtualMemory64 not found!"<<std::endl;
		}
#endif
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &proc_info64, sizeof(PROCESS_BASIC_INFORMATION64), NULL);
		if (!NT_SUCCESS(st)||!proc_info64.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetCmdCwdEnv:"<<__LINE__<<L": NtWow64QueryInformationProcess64(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
			return false;
		}
		
		PTR_64(PVOID) pRUPP64;
		//Requires PROCESS_VM_READ
		//proc_info64.PebBaseAddress, pRUPP64 and CommandLine64.Buffer pointers are already casted to integers
		if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, proc_info64.PebBaseAddress+offsetof(PEB64, ProcessParameters), &pRUPP64, sizeof(pRUPP64), NULL))) {
			UNICODE_STRING64 CommandLine64;
			CURDIR64 CurrentDirectory64;
			PTR_64(PVOID) Environment64;

			//GetCommandLine just returns RTL_USER_PROCESS_PARAMETER.CommandLine.Buffer
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, pRUPP64+offsetof(RTL_USER_PROCESS_PARAMETERS64, CommandLine), &CommandLine64, sizeof(CommandLine64), NULL))) {
				cmdline.reset(new wchar_t[CommandLine64.MaximumLength/sizeof(wchar_t)]);
				if (!NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, CommandLine64.Buffer, cmdline.get(), CommandLine64.MaximumLength, NULL))) return false;
			} else return false;
		
			//GetCurrentDirectory always terminates RTL_USER_PROCESS_PARAMETER.CurrentDirectory.DosPath.Buffer with NULL
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, pRUPP64+offsetof(RTL_USER_PROCESS_PARAMETERS64, CurrentDirectory), &CurrentDirectory64, sizeof(CurrentDirectory64), NULL))) {
				cwdpath.reset(new wchar_t[CurrentDirectory64.DosPath.Length/sizeof(wchar_t)+1]);
				cwdpath[CurrentDirectory64.DosPath.Length/sizeof(wchar_t)]=L'\0';
				if (!NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, CurrentDirectory64.DosPath.Buffer, cwdpath.get(), CurrentDirectory64.DosPath.Length, NULL))) return false;
			} else return false;
		
			//RTL_USER_PROCESS_PARAMETER.Environment contains continous block of memory allocated with NtAllocateVirtualMemory
			//NtWow64QueryVirtualMemory64 was available on WoW64 only for limited time - from Win XP x64 to Win 8.1
			//But since Win Vista RTL_USER_PROCESS_PARAMETERS contains EnvironmentSize
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, pRUPP64+offsetof(RTL_USER_PROCESS_PARAMETERS64, Environment), &Environment64, sizeof(Environment64), NULL))) {
				if (fnNtWow64QueryVirtualMemory64) {
					MEMORY_BASIC_INFORMATION64 env_mbi64;
					
					if (!NT_SUCCESS(fnNtWow64QueryVirtualMemory64(hProcess, Environment64, MemoryBasicInformation, &env_mbi64, sizeof(MEMORY_BASIC_INFORMATION64), NULL))) return false;
					SIZE_T env_len=env_mbi64.RegionSize-(Environment64-env_mbi64.BaseAddress);
					envblock.reset(new BYTE[env_len]);
					if (!NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, Environment64, envblock.get(), env_len, NULL))) return false;
				} else {
					ULONG env_len;
					
					if (!NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, pRUPP64+offsetof(RTL_USER_PROCESS_PARAMETERS64_VISTA, EnvironmentSize), &env_len, sizeof(env_len), NULL))) return false;
					envblock.reset(new BYTE[env_len]);
					if (!NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, Environment64, envblock.get(), env_len, NULL))) return false;
				}
			} else return false;
			
			return true;
		}
#endif	//_WIN64 ***********************************
	}
	
	return false;
}
