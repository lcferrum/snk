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
	ProcessesPolicy(), KillersPolicy(), ctrl_vars{true}, sec_mutex(NULL)
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
	if (sec_mutex) {
		std::wcout<<L"Secured execution: this instance is already secured!"<<std::endl;
		return false;
	}
	
	PSECURITY_DESCRIPTOR p_mutex_sd;
	if (!(p_mutex_sd=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) return false; 
	if (!InitializeSecurityDescriptor(p_mutex_sd, SECURITY_DESCRIPTOR_REVISION)) return false;
	if (!SetSecurityDescriptorDacl(p_mutex_sd, true, (PACL)NULL, true)) return false;
	
	SECURITY_ATTRIBUTES mutex_sa={sizeof(SECURITY_ATTRIBUTES), p_mutex_sd, false};
	sec_mutex=CreateMutex(&mutex_sa, false, MUTEX_NAME);
	LocalFree(p_mutex_sd);
	
	if (sec_mutex) {
		if (GetLastError()==ERROR_ALREADY_EXISTS) {
			std::wcout<<L"Secured execution: another secured SnK instance is already running!"<<std::endl;
			CloseHandle(sec_mutex);
			sec_mutex=NULL;
			return true;
		} else {
			std::wcout<<L"Secured execution: SnK instance secured!"<<std::endl;
			return false;
		}
	}
	
	return false;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath)
{
	//std::wcout<<L"Loading additional commands from \""<<arg_cmdpath<<"\"."<<std::endl;
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
	if (rules.empty()) return false;
	
	bool done=false;
	std::wstring top_rule=std::move(rules.top());
	rules.pop();
	
	if (!top_rule.compare(L"+t")) {
		ctrl_vars.mode_blank=true;
	} else if (!top_rule.compare(L"-t")) {
		ctrl_vars.mode_blank=false;
	} else if (!top_rule.compare(L"+i")) {
		ctrl_vars.mode_ignore=true;
	} else if (!top_rule.compare(L"-i")) {
		ctrl_vars.mode_ignore=false;
	} else if (!top_rule.compare(L"+v")) {
		ctrl_vars.mode_verbose=true;
	} else if (!top_rule.compare(L"-v")) {
		ctrl_vars.mode_verbose=false;
	} else if (!top_rule.compare(L"+a")) {
		ctrl_vars.mode_all=true;
	} else if (!top_rule.compare(L"-a")) {
		ctrl_vars.mode_all=false;
	} else if (!top_rule.compare(L"+l")) {
		ctrl_vars.mode_loop=true;
	} else if (!top_rule.compare(L"-l")) {
		ctrl_vars.mode_loop=false;
	} else if (!top_rule.compare(L"/blk:full")) {
		if (ctrl_vars.param_blk_mode==BlkMode::DEFAULT)
			ctrl_vars.param_blk_mode=BlkMode::FULL;
		else
			std::wcerr<<L"Warning: /blk:full parameter discarded!"<<std::endl;
	} else if (!top_rule.compare(L"/blk:clear")) {
		if (ctrl_vars.param_blk_mode==BlkMode::DEFAULT)
			ctrl_vars.param_blk_mode=BlkMode::CLEAR;
		else
			std::wcerr<<L"Warning: /blk:clear parameter discarded!"<<std::endl;
	} else if (!top_rule.compare(L"/blk:pid")) {
		if (ctrl_vars.param_blk_mode==BlkMode::DEFAULT)
			ctrl_vars.param_blk_mode=BlkMode::PID;
		else
			std::wcerr<<L"Warning: /blk:pid parameter discarded!"<<std::endl;
	} else if (!top_rule.compare(L"/blk")) {
		if (ctrl_vars.param_blk_mode==BlkMode::CLEAR) {
			NoArgsAllowed(L"/blk:clear");
			ClearBlacklist();
		} else if (ctrl_vars.param_blk_mode==BlkMode::PID)
			AddPidToBlacklist(ctrl_vars.args.c_str());
		else
			AddPathToBlacklist(ctrl_vars.param_blk_mode==BlkMode::FULL, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/bpp")) {
		NoArgsAllowed(top_rule);
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/sec")) {
		NoArgsAllowed(top_rule);
		while ((done=SecuredExecution())&&ctrl_vars.mode_loop) 
			Sleep(1000);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/cmd")) {
		ProcessCmdFile(rules, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/hlp")) {
		if (ctrl_vars.first_run) {
			PrintUsage();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /hlp switch will be ignored!"<<std::endl;
	} else if (!top_rule.compare(L"/ver")) {
		if (ctrl_vars.first_run) {
			PrintVersion();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			std::wcerr<<L"Warning: /ver switch will be ignored!"<<std::endl;
	} else if (!top_rule.compare(L"/cpu")) {
		NoArgsAllowed(top_rule);
		done=KillByCpu();
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pth:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/pth")) {
		done=KillByPth(ctrl_vars.param_full, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/mod:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/mod")) {
		done=KillByMod(ctrl_vars.param_full, ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pid")) {
		done=KillByPid(ctrl_vars.args.c_str());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/d3d:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/d3d")) {
		NoArgsAllowed(top_rule);
		done=KillByD3d(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/ogl:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/ogl")) {
		NoArgsAllowed(top_rule);
		done=KillByOgl(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/gld:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/gld")) {
		NoArgsAllowed(top_rule);
		done=KillByGld(ctrl_vars.param_simple);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/inr:vista")) {
		if (ctrl_vars.param_mode==InrMode::DEFAULT)
			ctrl_vars.param_mode=InrMode::VISTA;
		else
			std::wcerr<<L"Warning: /inr:vista parameter will be ignored!"<<std::endl;
	} else if (!top_rule.compare(L"/inr:manual")) {
		if (ctrl_vars.param_mode==InrMode::DEFAULT)
			ctrl_vars.param_mode=InrMode::MANUAL;
		else
			std::wcerr<<L"Warning: /inr:manual parameter will be ignored!"<<std::endl;
	} else if (!top_rule.compare(L"/inr")) {
		NoArgsAllowed(top_rule);
		done=KillByInr(ctrl_vars.param_mode);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fsc:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fsc:primary")) {
		ctrl_vars.param_primary=true;
	} else if (!top_rule.compare(L"/fsc")) {
		NoArgsAllowed(top_rule);
		done=KillByFsc(ctrl_vars.param_anywnd, ctrl_vars.param_primary);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fgd")) {
		NoArgsAllowed(top_rule);
		done=KillByFgd();
		ClearParamsAndArgs();
	} else if (top_rule.front()==L'=') {
		ctrl_vars.args=top_rule.substr(1);
	} else {
		if (top_rule.front()==L'+'||top_rule.front()==L'-') {
			std::wcerr<<L"Warning: unknown setting "<<top_rule<<L"!"<<std::endl;
		} else {
			if (top_rule.find(L':')!=std::wstring::npos) {
				std::wcerr<<L"Warning: unknown parameter "<<top_rule<<L"!"<<std::endl;
			} else {
				std::wcerr<<L"Warning: unknown switch "<<top_rule<<L"!"<<std::endl;
				if (!ctrl_vars.args.empty()) {
					std::wcerr<<L"Warning: no arguments allowed for unknown switch (\""<<ctrl_vars.args<<L"\")!"<<std::endl;
					ctrl_vars.args.clear();
				}
			}
		}
	}

	ctrl_vars.first_run=false;
	return !done||ctrl_vars.mode_ignore;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::MakeItDead(std::stack<std::wstring> &rules)
{
	while (MakeItDeadInternal(rules));
	
	if (ctrl_vars.mode_verbose) WaitForUserInput();
	
	if (sec_mutex) { 
		CloseHandle(sec_mutex);
		sec_mutex=NULL;
	}
	
	ctrl_vars={true};
}

template class Controller<Processes, Killers>;
