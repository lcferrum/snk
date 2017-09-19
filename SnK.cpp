#include <stack>
#include <cstdio>
#include <cwchar>
#include <iostream>
#include "ProcessUsage.h"
#include "AccessHacks.h"
#include "Controller.h"
#include "Killers.h"
#include "Extras.h"
#include "Common.h"
#include "Hout.h"

extern pWcoutMessageBox fnWcoutMessageBox;
extern template class Controller<Processes, Killers>;

#ifdef OBSOLETE_WMAIN
typedef struct {
	int newmode;
} _startupinfo;
#undef _CRT_glob
extern int _CRT_glob;
extern "C" void __wgetmainargs(int*, wchar_t***, wchar_t***, int, _startupinfo*);

int main()
{
	wchar_t **enpv, **argv;
	int argc;
	_startupinfo si;
	__wgetmainargs(&argc, &argv, &enpv, _CRT_glob, &si);
#else
extern "C" int wmain(int argc, wchar_t* argv[])
{
#endif
#ifdef HIDDEN
	Extras::MakeInstance(true, L"Search and Kill");
#else
	Extras::MakeInstance(false, NULL);
#endif

	if (argc<2) {
		PrintVersion();
#ifdef HIDDEN
		if (fnWcoutMessageBox) {
			std::wcout<<L"When finished, press OK..."<<std::endl;
			fnWcoutMessageBox();
		}
#endif
		return 0;
	}
	
	CoInitialize(NULL);								//COM is needed for GetLongPathName implementation from newapis.h
	AccessHacks::MakeInstance();

	AccessHacks::EnableDebugPrivileges();			//Will set debug privileges (administrator privileges should be already present for this to actually work) needed for OpenProcess to work succesfully on all non-user processes
	AccessHacks::ImpersonateLocalSystem();			//OpenProcessToken will fail on some system processes and foreign user processes if not done under Local System account even if done with debug privileges
	AccessHacks::Wow64DisableWow64FsRedirection();	//Turning off Wow64FsRedirection so GetLongPathName and GetFileAttributes uses correct path
	//A note on disabling Wow64FsRedirection
	//Microsoft discourages to do this process-wide and suggests disabling it right before the needed function call and reverting after
	//Main concerns here being LoadLibrary calls and delayed-loaded imports that may occur after Wow64FsRedirection being disabled and failing because of that
	//But delayed-loaded imports are not supported by current SnK distribution - so it's not of concern here
	//We just have to do all the LoadLibrary calls before disabling Wow64FsRedirection (which is already done through Extras class) and we are good to go
	//IUnknown::QueryInterface calls may lead to additional LoadLibrary calls
	//But the only place where COM is used is in GetLongPathName implementation from newapis.h and it is employed only on 32-bit systems where native GetLongPathName may not be readily available
	
	std::stack<std::wstring> rules;
	MakeRulesFromArgv(argc, argv, rules);
	Controller<Processes, Killers> controller;
	controller.MakeItDead(rules);
	
	AccessHacks::Wow64RevertWow64FsRedirection();
	AccessHacks::RevertToSelf();
	
	CoUninitialize();
	
	CachedNtQuerySystemProcessInformation(NULL, true);
	CachedNtQuerySystemHandleInformation(NULL, true);

	return 0;
}
