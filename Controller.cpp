#include "Extras.h"
#include "Common.h"
#include "Killers.h"
#include "Controller.h"
#include <stdio.h>
#include <iostream>
#include <limits>	//numeric_limits
#include <conio.h>

#define MUTEX_NAME	L"Global\\MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

extern pWcoutMessageBox fnWcoutMessageBox;

template <typename ProcessesPolicy, typename KillersPolicy>	
Controller<ProcessesPolicy, KillersPolicy>::Controller():
	ProcessesPolicy(), KillersPolicy(), Vars{true}
{}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::NoArgsAllowed(const std::wstring &sw) 
{
	if (!Vars.args.empty())
		std::wcerr<<L"Warning: switch "<<sw<<L" doesn't allow arguments (\""<<Vars.args<<L"\")!"<<std::endl;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::WaitForUserInput()
{
#ifdef HIDDEN
	if (fnWcoutMessageBox) {
		std::wcout<<L"Press OK to continue... "<<std::endl;
		fnWcoutMessageBox();
	}
#else
	std::wcout<<L"Press ENTER to continue... "<<std::flush;
	std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');	//Needs defined NOMINMAX
#endif
}

template <typename ProcessesPolicy, typename KillersPolicy>	
bool Controller<ProcessesPolicy, KillersPolicy>::SecuredExecution()
{
	SECURITY_ATTRIBUTES mutex_sa;
	PSECURITY_DESCRIPTOR p_mutex_sd;
	
	if (Vars.sec_mutex) {
		std::wcout<<L"Secured execution: this instance is already secured!"<<std::endl;
		return false;
	}
	
	if (!(p_mutex_sd=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) return false; 
	if (!InitializeSecurityDescriptor(p_mutex_sd, SECURITY_DESCRIPTOR_REVISION)) return false;
	if (!SetSecurityDescriptorDacl(p_mutex_sd, true, (PACL)NULL, true)) return false;
	mutex_sa.nLength=sizeof(SECURITY_ATTRIBUTES); 
	mutex_sa.lpSecurityDescriptor=p_mutex_sd;
	mutex_sa.bInheritHandle=false; 
	Vars.sec_mutex=CreateMutex(&mutex_sa, false, MUTEX_NAME);
	LocalFree(p_mutex_sd);
	
	if (Vars.sec_mutex) {
		if (GetLastError()==ERROR_ALREADY_EXISTS) {
			std::wcout<<L"Secured execution: another secured SnK instance is already running!"<<std::endl;
			CloseHandle(Vars.sec_mutex);
			Vars.sec_mutex=NULL;
			return true;
		} else {
			std::wcout<<L"Secured execution: SnK instance secured!"<<std::endl;
			return false;
		}
	}
	
	return false;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::ClearParamsAndArgs()
{
	Vars.param_first=false;
	Vars.param_second=false;
	Vars.args.clear();
}

template <typename ProcessesPolicy, typename KillersPolicy>	
bool Controller<ProcessesPolicy, KillersPolicy>::MakeItDeadInternal(std::stack<std::wstring> &In)
{
	bool Done=false;
	
    if (In.empty()) return false;
	
	if (!In.top().compare(L"+t")) {
		Vars.mode_blank=true;
	} else if (!In.top().compare(L"-t")) {
		Vars.mode_blank=false;
	} else if (!In.top().compare(L"+i")) {
		Vars.mode_ignore=true;
	} else if (!In.top().compare(L"-i")) {
		Vars.mode_ignore=false;
	} else if (!In.top().compare(L"+v")) {
		Vars.mode_verbose=true;
	} else if (!In.top().compare(L"-v")) {
		Vars.mode_verbose=false;
	} else if (!In.top().compare(L"+a")) {
		Vars.mode_all=true;
	} else if (!In.top().compare(L"-a")) {
		Vars.mode_all=false;
	} else if (!In.top().compare(L"+l")) {
		Vars.mode_loop=true;
	} else if (!In.top().compare(L"-l")) {
		Vars.mode_loop=false;
	} else if (!In.top().compare(L"/blk:full")) {
		Vars.param_full=true;
	} else if (!In.top().compare(L"/blk:clear")) {
		Vars.param_clear=true;
	} else if (!In.top().compare(L"/blk")) {
		if (Vars.param_clear) {
			if (Vars.param_full) std::wcerr<<L"Warning: /blk:full parameter will be ignored!"<<std::endl;
			NoArgsAllowed(L"/blk:clear");
			ClearBlacklist();
		} else
			AddToBlacklist(Vars.param_full, Vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/bpp")) {
		NoArgsAllowed(In.top());
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/sec")) {
		NoArgsAllowed(In.top());
		while ((Done=SecuredExecution())&&Vars.mode_loop) 
			Sleep(1000);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/hlp")) {
		if (Vars.first_run) {
			PrintUsage();
			Done=true;
#ifdef HIDDEN
			Vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /hlp switch will be ignored!"<<std::endl;
	} else if (!In.top().compare(L"/ver")) {
		if (Vars.first_run) {
			PrintVersion();
			Done=true;
#ifdef HIDDEN
			Vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /ver switch will be ignored!"<<std::endl;
	} else if (!In.top().compare(L"/cpu")) {
		NoArgsAllowed(In.top());
		Done=KillByCpu();
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/pth:full")) {
		Vars.param_full=true;
	} else if (!In.top().compare(L"/pth")) {
		Done=KillByPth(Vars.param_full, Vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/mod:full")) {
		Vars.param_full=true;
	} else if (!In.top().compare(L"/mod")) {
		Done=KillByMod(Vars.param_full, Vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/pid")) {
		Done=KillByPid(Vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/d3d:simple")) {
		Vars.param_simple=true;
	} else if (!In.top().compare(L"/d3d:soft")) {
		Vars.param_soft=true;
	} else if (!In.top().compare(L"/d3d")) {
		NoArgsAllowed(In.top());
		Done=KillByD3d(Vars.param_simple, Vars.param_soft);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/ogl:simple")) {
		Vars.param_simple=true;
	} else if (!In.top().compare(L"/ogl:soft")) {
		Vars.param_soft=true;
	} else if (!In.top().compare(L"/ogl")) {
		NoArgsAllowed(In.top());
		Done=KillByOgl(Vars.param_simple, Vars.param_soft);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/d2d:simple")) {
		Vars.param_simple=true;
	} else if (!In.top().compare(L"/d2d:strict")) {
		Vars.param_strict=true;
	} else if (!In.top().compare(L"/d2d")) {
		NoArgsAllowed(In.top());
		Done=KillByD2d(Vars.param_simple, Vars.param_strict);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/gld:simple")) {
		Vars.param_simple=true;
	} else if (!In.top().compare(L"/gld:strict")) {
		Vars.param_strict=true;
	} else if (!In.top().compare(L"/gld")) {
		NoArgsAllowed(In.top());
		Done=KillByGld(Vars.param_simple, Vars.param_strict);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/inr:vista")) {
		if (Vars.param_mode==InrMode::DEFAULT)
			Vars.param_mode=InrMode::VISTA;
		else
			std::wcerr<<L"Warning: /inr:vista parameter will be ignored!"<<std::endl;
	} else if (!In.top().compare(L"/inr:manual")) {
		if (Vars.param_mode==InrMode::DEFAULT)
			Vars.param_mode=InrMode::MANUAL;
		else
			std::wcerr<<L"Warning: /inr:manual parameter will be ignored!"<<std::endl;
	} else if (!In.top().compare(L"/inr")) {
		NoArgsAllowed(In.top());
		Done=KillByInr(Vars.param_mode);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/fsc:anywnd")) {
		Vars.param_anywnd=true;
	} else if (!In.top().compare(L"/fsc:primary")) {
		Vars.param_primary=true;
	} else if (!In.top().compare(L"/fsc")) {
		NoArgsAllowed(In.top());
		Done=KillByFsc(Vars.param_anywnd, Vars.param_primary);
		ClearParamsAndArgs();
	} else if (!In.top().compare(L"/fgd")) {
		NoArgsAllowed(In.top());
		Done=KillByFgd();
		ClearParamsAndArgs();
	} else if (In.top().front()==L'=') {
		Vars.args=In.top().substr(1);
	} else {
		if (In.top().front()==L'+'||In.top().front()==L'-') {
			std::wcerr<<L"Warning: unknown setting "<<In.top()<<L"!"<<std::endl;
		} else {
			if (In.top().find(L':')!=std::wstring::npos) {
				std::wcerr<<L"Warning: unknown parameter "<<In.top()<<L"!"<<std::endl;
			} else {
				std::wcerr<<L"Warning: unknown switch "<<In.top()<<L"!"<<std::endl;
				if (!Vars.args.empty()) {
					std::wcerr<<L"Warning: no arguments allowed for unknown switch (\""<<Vars.args<<L"\")!"<<std::endl;
					Vars.args.clear();
				}
			}
		}
	}

	In.pop();
	Vars.first_run=false;
	return !In.empty()&&(!Done||Vars.mode_ignore);
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::MakeItDead(std::stack<std::wstring> &In)
{
	while (MakeItDeadInternal(In));
	
	if (Vars.mode_verbose) WaitForUserInput();
	
	if (Vars.sec_mutex) CloseHandle(Vars.sec_mutex);
	
	Vars={true};
}

template class Controller<Processes, Killers>;
