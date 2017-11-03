#include "Externs.h"

pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow=NULL;
pNtQuerySystemInformation fnNtQuerySystemInformation=NULL;
pNtOpenSymbolicLinkObject fnNtOpenSymbolicLinkObject=NULL;
pNtQuerySymbolicLinkObject fnNtQuerySymbolicLinkObject=NULL;
pNtCreateFile fnNtCreateFile=NULL;
pNtQueryInformationFile fnNtQueryInformationFile=NULL;
pNtQueryObject fnNtQueryObject=NULL;
pNtQueryInformationProcess fnNtQueryInformationProcess=NULL;
pNtWow64QueryInformationProcess64 fnNtWow64QueryInformationProcess64=NULL;
pNtWow64ReadVirtualMemory64 fnNtWow64ReadVirtualMemory64=NULL;
pIsWow64Process fnIsWow64Process=NULL;
pPathFindOnPathW fnPathFindOnPathW=NULL;
pWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection=NULL;
pWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection=NULL;
pNtQueryVirtualMemory fnNtQueryVirtualMemory=NULL;
pNtWow64QueryVirtualMemory64 fnNtWow64QueryVirtualMemory64=NULL;
pAttachConsole fnAttachConsole=NULL;
pGetConsoleWindow fnGetConsoleWindow=NULL;
pGetProcessMemoryInfo fnGetProcessMemoryInfo=NULL;

std::unique_ptr<Externs> Externs::instance;

Externs::Externs(): 
	hUser32(NULL), hNtDll(NULL), hKernel32(NULL), hShlwapi(NULL), hPsapi(NULL)
{
	LoadFunctions();
}

Externs::~Externs() 
{
	UnloadFunctions();
}

bool Externs::MakeInstance() 
{
	if (instance)
		return false;
	
	instance.reset(new Externs());
	return true;
}

//Checking if DLLs are alredy loaded before LoadLibrary is cool but redundant
//This method is private and called (and designed to be called) only once - in constructor before everything else
void Externs::LoadFunctions() 
{
	hUser32=LoadLibrary(L"user32.dll");
	hNtDll=LoadLibrary(L"ntdll.dll");
	hKernel32=LoadLibrary(L"kernel32.dll");
	hShlwapi=LoadLibrary(L"shlwapi.dll");
	hPsapi=LoadLibrary(L"psapi.dll");

	if (hUser32) {
		fnNtUserHungWindowFromGhostWindow=(pNtUserHungWindowFromGhostWindow)GetProcAddress(hUser32, "HungWindowFromGhostWindow");
	}
	
	if (hNtDll) {
		fnNtQuerySystemInformation=(pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
		fnNtCreateFile=(pNtCreateFile)GetProcAddress(hNtDll, "NtCreateFile");
		fnNtQueryInformationFile=(pNtQueryInformationFile)GetProcAddress(hNtDll, "NtQueryInformationFile");
		fnNtQueryObject=(pNtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
		fnNtOpenSymbolicLinkObject=(pNtOpenSymbolicLinkObject)GetProcAddress(hNtDll, "NtOpenSymbolicLinkObject");
		fnNtQuerySymbolicLinkObject=(pNtQuerySymbolicLinkObject)GetProcAddress(hNtDll, "NtQuerySymbolicLinkObject");
		fnNtQueryInformationProcess=(pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		fnNtWow64QueryInformationProcess64=(pNtWow64QueryInformationProcess64)GetProcAddress(hNtDll, "NtWow64QueryInformationProcess64");
		fnNtWow64ReadVirtualMemory64=(pNtWow64ReadVirtualMemory64)GetProcAddress(hNtDll, "NtWow64ReadVirtualMemory64");
		fnNtQueryVirtualMemory=(pNtQueryVirtualMemory)GetProcAddress(hNtDll, "NtQueryVirtualMemory");
		fnNtWow64QueryVirtualMemory64=(pNtWow64QueryVirtualMemory64)GetProcAddress(hNtDll, "NtWow64QueryVirtualMemory64");
	}
	
	if (hKernel32) {
		fnIsWow64Process=(pIsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
		fnWow64DisableWow64FsRedirection=(pWow64DisableWow64FsRedirection)GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection");
		fnWow64RevertWow64FsRedirection=(pWow64RevertWow64FsRedirection)GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection");
		fnAttachConsole=(pAttachConsole)GetProcAddress(hKernel32, "AttachConsole");
		fnGetConsoleWindow=(pGetConsoleWindow)GetProcAddress(hKernel32, "GetConsoleWindow");
	}
	
	if (hShlwapi) {
		fnPathFindOnPathW=(pPathFindOnPathW)GetProcAddress(hShlwapi, "PathFindOnPathW");
	}
	
	if (hPsapi) {
		fnGetProcessMemoryInfo=(pGetProcessMemoryInfo)GetProcAddress(hPsapi, "GetProcessMemoryInfo");
	}
}

//And here we are testing for NULLs because LoadLibrary can fail in method above
void Externs::UnloadFunctions() 
{
	if (hUser32) FreeLibrary(hUser32);
	if (hNtDll) FreeLibrary(hNtDll);
	if (hKernel32) FreeLibrary(hKernel32);
	if (hShlwapi) FreeLibrary(hShlwapi);
	if (hPsapi) FreeLibrary(hPsapi);
}
