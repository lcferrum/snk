#include "Extras.h"
#include "Common.h"
#include "Killers.h"
#include "Controller.h"
#include <stdio.h>
#include <iostream>
#include <limits>	//numeric_limits
#include <conio.h>

#define MUTEX_NAME		L"MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

extern pWcoutMessageBox fnWcoutMessageBox;

template <typename ProcessesPolicy, typename KillersPolicy>	
Controller<ProcessesPolicy, KillersPolicy>::Controller():
	ProcessesPolicy(), KillersPolicy(), ctrl_vars{true}
{}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::NoArgsAllowed(const std::wstring &sw) 
{
	if (!ctrl_vars.args.empty())
		std::wcerr<<L"Warning: switch "<<sw<<L" doesn't allow arguments (\""<<ctrl_vars.args<<L"\")!"<<std::endl;
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
	if (ctrl_vars.sec_mutex) {
		std::wcout<<L"Secured execution: this instance is already secured!"<<std::endl;
		return false;
	}
	
	PSECURITY_DESCRIPTOR p_mutex_sd;
	if (!(p_mutex_sd=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) return false; 
	if (!InitializeSecurityDescriptor(p_mutex_sd, SECURITY_DESCRIPTOR_REVISION)) return false;
	if (!SetSecurityDescriptorDacl(p_mutex_sd, true, (PACL)NULL, true)) return false;
	
	SECURITY_ATTRIBUTES mutex_sa={sizeof(SECURITY_ATTRIBUTES), p_mutex_sd, false};
	ctrl_vars.sec_mutex=CreateMutex(&mutex_sa, false, MUTEX_NAME);
	LocalFree(p_mutex_sd);
	
	if (ctrl_vars.sec_mutex) {
		if (GetLastError()==ERROR_ALREADY_EXISTS) {
			std::wcout<<L"Secured execution: another secured SnK instance is already running!"<<std::endl;
			CloseHandle(ctrl_vars.sec_mutex);
			ctrl_vars.sec_mutex=NULL;
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
	ctrl_vars.param_first=false;
	ctrl_vars.param_second=false;
	ctrl_vars.args.clear();
}

template <typename ProcessesPolicy, typename KillersPolicy>	
bool Controller<ProcessesPolicy, KillersPolicy>::MakeItDeadInternal(std::stack<std::wstring> &rules)
{
	bool done=false;
	
	if (rules.empty()) return false;
	
	if (!rules.top().compare(L"+t")) {
		ctrl_vars.mode_blank=true;
	} else if (!rules.top().compare(L"-t")) {
		ctrl_vars.mode_blank=false;
	} else if (!rules.top().compare(L"+i")) {
		ctrl_vars.mode_ignore=true;
	} else if (!rules.top().compare(L"-i")) {
		ctrl_vars.mode_ignore=false;
	} else if (!rules.top().compare(L"+v")) {
		ctrl_vars.mode_verbose=true;
	} else if (!rules.top().compare(L"-v")) {
		ctrl_vars.mode_verbose=false;
	} else if (!rules.top().compare(L"+a")) {
		ctrl_vars.mode_all=true;
	} else if (!rules.top().compare(L"-a")) {
		ctrl_vars.mode_all=false;
	} else if (!rules.top().compare(L"+l")) {
		ctrl_vars.mode_loop=true;
	} else if (!rules.top().compare(L"-l")) {
		ctrl_vars.mode_loop=false;
	} else if (!rules.top().compare(L"/blk:full")) {
		ctrl_vars.param_full=true;
	} else if (!rules.top().compare(L"/blk:clear")) {
		ctrl_vars.param_clear=true;
	} else if (!rules.top().compare(L"/blk")) {
		if (ctrl_vars.param_clear) {
			if (ctrl_vars.param_full) std::wcerr<<L"Warning: /blk:full parameter will be ignored!"<<std::endl;
			NoArgsAllowed(L"/blk:clear");
			ClearBlacklist();
		} else
			AddToBlacklist(ctrl_vars.param_full, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/bpp")) {
		NoArgsAllowed(rules.top());
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/sec")) {
		NoArgsAllowed(rules.top());
		while ((done=SecuredExecution())&&ctrl_vars.mode_loop) 
			Sleep(1000);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/hlp")) {
		if (ctrl_vars.first_run) {
			PrintUsage();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /hlp switch will be ignored!"<<std::endl;
	} else if (!rules.top().compare(L"/ver")) {
		if (ctrl_vars.first_run) {
			PrintVersion();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /ver switch will be ignored!"<<std::endl;
	} else if (!rules.top().compare(L"/cpu")) {
		NoArgsAllowed(rules.top());
		done=KillByCpu();
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/pth:full")) {
		ctrl_vars.param_full=true;
	} else if (!rules.top().compare(L"/pth")) {
		done=KillByPth(ctrl_vars.param_full, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/mod:full")) {
		ctrl_vars.param_full=true;
	} else if (!rules.top().compare(L"/mod")) {
		done=KillByMod(ctrl_vars.param_full, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/pid")) {
		done=KillByPid(ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/d3d:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!rules.top().compare(L"/d3d")) {
		NoArgsAllowed(rules.top());
		done=KillByD3d(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/ogl:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!rules.top().compare(L"/ogl")) {
		NoArgsAllowed(rules.top());
		done=KillByOgl(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/gld:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!rules.top().compare(L"/gld")) {
		NoArgsAllowed(rules.top());
		done=KillByGld(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/inr:vista")) {
		if (ctrl_vars.param_mode==InrMode::DEFAULT)
			ctrl_vars.param_mode=InrMode::VISTA;
		else
			std::wcerr<<L"Warning: /inr:vista parameter will be ignored!"<<std::endl;
	} else if (!rules.top().compare(L"/inr:manual")) {
		if (ctrl_vars.param_mode==InrMode::DEFAULT)
			ctrl_vars.param_mode=InrMode::MANUAL;
		else
			std::wcerr<<L"Warning: /inr:manual parameter will be ignored!"<<std::endl;
	} else if (!rules.top().compare(L"/inr")) {
		NoArgsAllowed(rules.top());
		done=KillByInr(ctrl_vars.param_mode);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/fsc:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!rules.top().compare(L"/fsc:primary")) {
		ctrl_vars.param_primary=true;
	} else if (!rules.top().compare(L"/fsc")) {
		NoArgsAllowed(rules.top());
		done=KillByFsc(ctrl_vars.param_anywnd, ctrl_vars.param_primary);
		ClearParamsAndArgs();
	} else if (!rules.top().compare(L"/fgd")) {
		NoArgsAllowed(rules.top());
		done=KillByFgd();
		ClearParamsAndArgs();
	} else if (rules.top().front()==L'=') {
		ctrl_vars.args=rules.top().substr(1);
	} else {
		if (rules.top().front()==L'+'||rules.top().front()==L'-') {
			std::wcerr<<L"Warning: unknown setting "<<rules.top()<<L"!"<<std::endl;
		} else {
			if (rules.top().find(L':')!=std::wstring::npos) {
				std::wcerr<<L"Warning: unknown parameter "<<rules.top()<<L"!"<<std::endl;
			} else {
				std::wcerr<<L"Warning: unknown switch "<<rules.top()<<L"!"<<std::endl;
				if (!ctrl_vars.args.empty()) {
					std::wcerr<<L"Warning: no arguments allowed for unknown switch (\""<<ctrl_vars.args<<L"\")!"<<std::endl;
					ctrl_vars.args.clear();
				}
			}
		}
	}

	rules.pop();
	ctrl_vars.first_run=false;
	return !rules.empty()&&(!done||ctrl_vars.mode_ignore);
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::MakeItDead(std::stack<std::wstring> &rules)
{
	while (MakeItDeadInternal(rules));
	
	if (ctrl_vars.mode_verbose) WaitForUserInput();
	
	if (ctrl_vars.sec_mutex) CloseHandle(ctrl_vars.sec_mutex);
	
	ctrl_vars={true};
}

template class Controller<Processes, Killers>;
