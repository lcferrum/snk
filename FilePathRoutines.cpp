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

//Cut-down version of RTL_USER_PROCESS_PARAMETERS with x86 align
typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
	BYTE Reserved[56];
	UNICODE_STRING32 ImagePathName;
} RTL_USER_PROCESS_PARAMETERS32;

//Cut-down version of RTL_USER_PROCESS_PARAMETERS with x86_64 align
typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
	BYTE Reserved[96];
	UNICODE_STRING64 ImagePathName;
} RTL_USER_PROCESS_PARAMETERS64;

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

//Not using native RTL_USER_PROCESS_PARAMETERS, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY and PEB structures so to be sure in offset consistency
#ifdef _WIN64
	typedef RTL_USER_PROCESS_PARAMETERS64 RTL_USER_PROCESS_PARAMETERSXX;
	typedef PEB_LDR_DATA64 PEB_LDR_DATAXX;
	typedef LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRYXX;
	typedef PEB64 PEBXX;
#else
	typedef RTL_USER_PROCESS_PARAMETERS32 RTL_USER_PROCESS_PARAMETERSXX;
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
	bool KernelToWin32Path(const wchar_t* krn_fpath, std::wstring &w32_fpath);
	bool GetMappedFileNameWrapper(HANDLE hProcess, LPVOID hMod, std::wstring &fpath);
	bool GetMappedFileNameWow64Wrapper(HANDLE hProcess, PTR_64(PVOID) hMod, std::wstring &fpath);
	bool CommandLineToApplicationName(wchar_t *cmdline, std::wstring &appname);
	bool GetFP_ProcessImageFileNameWin32(HANDLE hProcess, std::wstring &fpath);
	bool GetFP_QueryServiceConfig(HANDLE PID, std::wstring &fpath);
	bool GetFP_PEB(HANDLE hProcess, std::wstring &fpath);
	bool GetFP_SystemProcessIdInformation(HANDLE PID, std::wstring &fpath);
	bool GetFP_ProcessImageFileName(HANDLE hProcess, std::wstring &fpath);
	std::wstring GetLongPathNameWrapper(const wchar_t* path);
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

std::wstring FPRoutines::GetFilePath(HANDLE PID, HANDLE hProcess, bool vm_read) 
{
#if DEBUG>=3
	std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Getting path for PID "<<(ULONG_PTR)PID<<L"..."<<std::endl;
#endif
	std::wstring fpath;
	
	if (
//		(hProcess&&GetFP_ProcessImageFileNameWin32(hProcess, fpath))||	//First we use NtQueryInformationProcess(ProcessImageFileNameWin32) to get file path: assuming that SnK is run with admin rights and current OS is likely to be Vista or above (it's a method requirement), we will get Win32 path for every process
		GetFP_QueryServiceConfig(PID, fpath)||							//If previous method failed, now starts guessing work: we assume that method most likely failed because of obsolete OS (because, hey, you'd better grant SnK admin rights to do it work properly!) - this is a pretty good method to get Win32 filepath, it doesn't require any rights, works on everything from NT4, the only downside being that it can only query services
		(hProcess&&vm_read&&GetFP_PEB(hProcess, fpath))||				//One more method for obsolete OSes: obtaining file path from PEB is complex (and may require kernel to Win32 path conversion), needs more security rights than every other method, but works on everything from NT4 and doesn't have limited scope like previous method
		GetFP_SystemProcessIdInformation(PID, fpath)||					//Previous methods failed so it seems that actually we doesn't have enough security rights (because previous two methods will get file path even from NT4 if given admin rights): NtQuerySystemInformation(SystemProcessIdInformation) is a good choice if current process is limited in rights, because it doesn't require any, but have two downsides - it works only on Vista and above and kernel to Win32 path conversion is mandatory
		(hProcess&&GetFP_ProcessImageFileName(hProcess, fpath))			//It's a last chance: maybe we have a not-completely-obsolete OS (like XP) and security limitations prevent us from accessing PEB but permit something less complex - NtQueryInformationProcess(ProcessImageFileName) works starting from XP, requires same amount of rights as the very first method but kernel to Win32 path conversion is mandatory
		) {
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Normalizing path with GetLongPathName: \""<<fpath<<L"\"..."<<std::endl;
#endif
		//There is a possibilty that returned path will include 8.3 portions (and be all-lowercase)
		//So it's better convert it to LFN (this also restores character case)
		//GetLongPathName is UNC aware, affected by Wow64FsRedirection, may fail because of security restrictions
		//Prepend returned path with "\\?\" so GetLongPathName won't fail if path length is more than MAX_PATH
		//N.B.:
		//GetLongPathName accepts slash as path deparator but not with "\\?\"
		//Also GetLongPathName doesn't convert slashes to backslashes in returned path
		//But it's not of concern here because none of GetFP functions is able to return path with slashes as path separator
		bool unc_path;
		if ((unc_path=fpath.front()==L'\\'))
			fpath.insert(1, L"\\?\\UNC");
		else
			fpath.insert(0, L"\\\\?\\");
		if (DWORD buf_len=Probe_GetLongPathName(fpath.c_str(), NULL, 0)) {
			wchar_t buffer[buf_len];
			if (Probe_GetLongPathName(fpath.c_str(), buffer, buf_len)) {
				//We now have valid (GetLongPathName fails if path doesn't exist - relative check) Win32 LFN file path
				//Removing "\\?\" prefix
				wchar_t* clean_buf=buffer+4;
				if (unc_path) *(clean_buf+=2)=L'\\';
#if DEBUG>=3
				std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": Found path for PID "<<(ULONG_PTR)PID<<L": \""<<clean_buf<<L"\""<<std::endl;
#endif
				return clean_buf;
			}
		}
#if DEBUG>=3
		std::wcerr<<L"" __FILE__ ":GetFilePath:"<<__LINE__<<L": GetLongPathName failed for PID "<<(ULONG_PTR)PID<<std::endl;
#endif
	}
	
	return L"";
}

std::wstring FPRoutines::GetLongPathNameWrapper(const wchar_t* path)
{
	if (DWORD buf_len=Probe_GetLongPathName(path, NULL, 0)) {
		wchar_t buffer[buf_len];
		if (Probe_GetLongPathName(path, buffer, buf_len)) {
			return buffer;
		}
	}
	return L"";
}

#define SELECTED_MODULE_LIST InMemoryOrderModuleList
std::vector<std::wstring> FPRoutines::GetModuleList(HANDLE hProcess, bool full) 
{
	std::vector<std::wstring> mlist;
	
	if (!hProcess)
		return {};
	
	if (!fnNtQueryInformationProcess) {
#if DEBUG>=2
		std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtQueryInformationProcess not found!"<<std::endl;
#endif
		return {};
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
			return {};
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
			return {};
		}
		
		//Requires PROCESS_VM_READ	
		//All members of PEBXX and LDR_DATA_TABLE_ENTRYXX are already casted to integers
		PEBXX pebXX;
		if (ReadProcessMemory(hProcess, proc_info.PebBaseAddress, &pebXX, sizeof(pebXX), NULL)) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRYXX ldteXX;
			if (ReadProcessMemory(hProcess, (LPCVOID)(pebXX.LdrData+offsetof(PEB_LDR_DATAXX, SELECTED_MODULE_LIST)), &ldteXX.SELECTED_MODULE_LIST, sizeof(LIST_ENTRY), NULL)&&ldteXX.SELECTED_MODULE_LIST.Flink) {
				while (ldteXX.SELECTED_MODULE_LIST.Flink!=(pebXX.LdrData+offsetof(PEB_LDR_DATAXX, SELECTED_MODULE_LIST))) {	//Enumerate all the list members till list closes
					if (ReadProcessMemory(hProcess, (LPCVOID)(ldteXX.SELECTED_MODULE_LIST.Flink-offsetof(LDR_DATA_TABLE_ENTRYXX, SELECTED_MODULE_LIST)), &ldteXX, sizeof(ldteXX), NULL)) {
						if (ldteXX.DllBase==pebXX.ImageBaseAddress)	//Skip process image entry
							continue;
							
						//Module paths can include 8.3 portions so normalize it with GetMappedFileName
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
				return mlist;
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
			return {};
		}
		
		//Requires PROCESS_VM_READ
		//PebBaseAddress32 and all members of PEB32 and LDR_DATA_TABLE_ENTRY32 are already casted to integers
		PEB32 peb32;
		if (ReadProcessMemory(hProcess, (LPCVOID)PebBaseAddress32, &peb32, sizeof(peb32), NULL)) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRY32 ldte32;
			if (ReadProcessMemory(hProcess, (LPCVOID)(peb32.LdrData+offsetof(PEB_LDR_DATA32, SELECTED_MODULE_LIST)), &ldte32.SELECTED_MODULE_LIST, sizeof(LIST_ENTRY), NULL)&&ldte32.SELECTED_MODULE_LIST.Flink) {
				while (ldte32.SELECTED_MODULE_LIST.Flink!=(peb32.LdrData+offsetof(PEB_LDR_DATA32, SELECTED_MODULE_LIST))) {	//Enumerate all the list members till list closes
					if (ReadProcessMemory(hProcess, (LPCVOID)(ldte32.SELECTED_MODULE_LIST.Flink-offsetof(LDR_DATA_TABLE_ENTRY32, SELECTED_MODULE_LIST)), &ldte32, sizeof(ldte32), NULL)) {
						if (ldte32.DllBase==peb32.ImageBaseAddress)	//Skip process image entry
							continue;
						
						//If current ptocess is 64-bit, surely we are on x64 OS and 32-bit process is run under WoW64
						//We should use GetMappedFileNameWrapper to undo WoW64 redirection
						//Module paths can include 8.3 portions so normalize it with GetMappedFileName
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
				return mlist;
			}
		}
#else	//_WIN64 ***********************************
		//Reading 64-bit process from 32-bit process
	
		if (!fnNtWow64QueryInformationProcess64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64QueryInformationProcess64 not found!"<<std::endl;
#endif
			return {};
		}
		
		if (!fnNtWow64ReadVirtualMemory64) {
#if DEBUG>=2
			std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64ReadVirtualMemory64 not found!"<<std::endl;
#endif
			return {};
		}
	
		//Requires PROCESS_QUERY_(LIMITED_)INFORMATION
		st=fnNtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &proc_info64, sizeof(PROCESS_BASIC_INFORMATION64), NULL);
		if (!NT_SUCCESS(st)||!proc_info64.PebBaseAddress) {
#if DEBUG>=2
			if (st==STATUS_INVALID_INFO_CLASS)
				std::wcerr<<L"" __FILE__ ":GetModuleList:"<<__LINE__<<L": NtWow64QueryInformationProcess64(ProcessImageFileName) failed - information class not supported!"<<std::endl;
#endif
			return {};
		}
		
		//Requires PROCESS_VM_READ
		//proc_info64.PebBaseAddress and all members of PEB64 and LDR_DATA_TABLE_ENTRY64 are already casted to integers
		PEB64 peb64;
		if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, proc_info64.PebBaseAddress, &peb64, sizeof(peb64), NULL))) {
			//One thing to remember is that Flink/Blink members of LIST_ENTRY don't actually point to the start of structures composing the list
			//They point to the LIST_ENTRY member of these structures that corresponds to the list currently being walked
			LDR_DATA_TABLE_ENTRY64 ldte64;
			if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, peb64.LdrData+offsetof(PEB_LDR_DATA64, SELECTED_MODULE_LIST), &ldte64.SELECTED_MODULE_LIST, sizeof(LIST_ENTRY), NULL))&&ldte64.SELECTED_MODULE_LIST.Flink) {
				while (ldte64.SELECTED_MODULE_LIST.Flink!=(peb64.LdrData+offsetof(PEB_LDR_DATA64, SELECTED_MODULE_LIST))) {	//Enumerate all the list members till list closes
					if (NT_SUCCESS(fnNtWow64ReadVirtualMemory64(hProcess, ldte64.SELECTED_MODULE_LIST.Flink-offsetof(LDR_DATA_TABLE_ENTRY64, SELECTED_MODULE_LIST), &ldte64, sizeof(ldte64), NULL))) {
						if (ldte64.DllBase==peb64.ImageBaseAddress)	//Skip process image entry
							continue;
							
						//Not using GetMappedFileNameWow64Wrapper here
						//First of all - it's not implemented because of underlaying NtWow64QueryVirtualMemory64 not being properly implemented on WoW64
						//Actually, we can just use ordinary GetMappedFileNameWrapper, but it will work only with modules which DllBase's HIDWORD is NULL
						//Second - actually we don't need no GetMappedFileNameWow64Wrapper or GetMappedFileNameWrapper here
						//The whole point of getting module path from it's handle is in getting rid of WoW64 path redirection mechanism which affects BaseDllName/FullDllName
						//But we are queryng x64 process - it's simply doesn't run on WoW64 so has nothing to do with WoW64 redirection
							
						//Returned paths are all in Win32 form (except image path that is skipped)
						//Module paths can include 8.3 portions so normalize it with GetMappedFileName
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
				return mlist;
			}
		}
#endif	//_WIN64 ***********************************
	}
	
	return {};
}

std::wstring FPRoutines::GetHandlePath(HANDLE hFile, bool full)
{
	/*
	DWORD buf_len=1024;
	BYTE oni_buf[buf_len];
	if (NT_SUCCESS(fnNtQueryObject(hDupFile, ObjectNameInformation, (OBJECT_NAME_INFORMATION*)oni_buf, buf_len, NULL))) {
		std::wcerr<<L"HANDLE PID="<<prc_pid<<L" ONI PATH: "<<((OBJECT_NAME_INFORMATION*)oni_buf)->Name.Buffer<<std::endl;
	} else
		std::wcerr<<L"HANDLE PID="<<prc_pid<<L" ONI ERROR"<<std::endl;
	IO_STATUS_BLOCK ioStatusBlock;
	BYTE fni_buf[buf_len];
	if (NT_SUCCESS(fnNtQueryInformationFile(hDupFile, &ioStatusBlock, (FILE_NAME_INFORMATION*)fni_buf, buf_len, FileNameInformation))) {
		std::wstring fpath(((FILE_NAME_INFORMATION*)fni_buf)->FileName, ((FILE_NAME_INFORMATION*)fni_buf)->FileNameLength/sizeof(wchar_t));
		std::wcerr<<L"HANDLE PID="<<prc_pid<<L" FNI PATH: "<<fpath<<std::endl;
	} else
		std::wcerr<<L"HANDLE PID="<<prc_pid<<L" FNI ERROR"<<std::endl;
	*/
	
	return L"";
}
