#include "Extras.h"
#include "Hout.h"

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
pAttachConsole fnAttachConsole=NULL;
pWcoutMessageBox fnWcoutMessageBox;

std::unique_ptr<Extras> Extras::instance;

Extras::Extras(bool hidden, const wchar_t* caption): 
	wcout_win32(true), wcerr_win32(false),
	hUser32(NULL), hNtDll(NULL), hKernel32(NULL), hShlwapi(NULL)
{
	LoadFunctions();
	
	wcout_win32.Activate();
	wcerr_win32.Activate();
	if (hidden) {
		wcout_win32.AttachMessageBox(caption?caption:L"");
		fnWcoutMessageBox=std::bind(&Extras::WcoutMessageBox, this);
	} else {
		CONSOLE_SCREEN_BUFFER_INFO csbi; 
		HANDLE hstdout;
		if ((hstdout=GetStdHandle(STD_OUTPUT_HANDLE))!=INVALID_HANDLE_VALUE)	//STD_OUTPUT_HANDLE - because Hout will output to std::wcout
			if (GetConsoleScreenBufferInfo(hstdout, &csbi))
				Hout::SetTerminalSize(csbi.dwSize.X);
	}
}

Extras::~Extras() {
	wcout_win32.Deactivate();	//Don't wait for destructor, deactivate Win32WcostreamBuf before unloading functions
	wcerr_win32.Deactivate();
	UnloadFunctions();
}

bool Extras::MakeInstance(bool hidden, const wchar_t* caption) 
{
	if (instance)
		return false;
	
	instance.reset(new Extras(hidden, caption));
	return true;
}

void Extras::WcoutMessageBox()
{
	wcout_win32.ShowMessageBox();
}

void Extras::LoadFunctions() 
{
	if (!hUser32) hUser32=LoadLibrary(L"user32.dll");
	if (!hNtDll) hNtDll=LoadLibrary(L"ntdll.dll");
	if (!hKernel32) hKernel32=LoadLibrary(L"kernel32.dll");
	if (!hShlwapi) hShlwapi=LoadLibrary(L"shlwapi.dll");

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
	}
	
	if (hKernel32) {
		fnIsWow64Process=(pIsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
		fnWow64DisableWow64FsRedirection=(pWow64DisableWow64FsRedirection)GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection");
		fnWow64RevertWow64FsRedirection=(pWow64RevertWow64FsRedirection)GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection");
		fnAttachConsole=(pAttachConsole)GetProcAddress(hKernel32, "AttachConsole");
	}
	
	if (hShlwapi) {
		fnPathFindOnPathW=(pPathFindOnPathW)GetProcAddress(hShlwapi, "PathFindOnPathW");
	}
}

void Extras::UnloadFunctions() 
{
	if (hUser32) FreeLibrary(hUser32);
	if (hNtDll) FreeLibrary(hNtDll);
	if (hKernel32) FreeLibrary(hKernel32);
	if (hShlwapi) FreeLibrary(hShlwapi);
}
