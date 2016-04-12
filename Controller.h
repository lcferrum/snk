#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stack>
#include <string>
#include <functional>
#include <windows.h>

template <typename ProcessesPolicy, typename KillersPolicy>	
class Controller: private ProcessesPolicy, private KillersPolicy {
	using ProcessesPolicy::AddToBlacklist;
	using ProcessesPolicy::ClearBlacklist;
	typedef typename KillersPolicy::InrMode InrMode;
	using KillersPolicy::KillByCpu;
	using KillersPolicy::KillByPth;
	using KillersPolicy::KillByMod;
	using KillersPolicy::KillByPid;
	using KillersPolicy::KillByD3d;
	using KillersPolicy::KillByOgl;
	using KillersPolicy::KillByD2d;
	using KillersPolicy::KillByGld;
	using KillersPolicy::KillByInr;
	using KillersPolicy::KillByFsc;
	using KillersPolicy::KillByFgd;
private:
	struct {
		bool first_run;
		bool mode_blank;
		bool mode_ignore;
		bool mode_all;
		bool mode_loop;
		bool mode_verbose;
		union {
			bool param_first;
			InrMode param_mode;
			bool param_full;
			bool param_simple;
			bool param_anywnd;
		};
		union {
			bool param_second;
			bool param_clear;
			bool param_soft;
			bool param_strict;
			bool param_primary;
		}; 
		std::wstring args;
		HANDLE sec_mutex;
	} Vars;
	
	void ClearParamsAndArgs();
	void NoArgsAllowed(const std::wstring &sw);
	void WaitForUserInput();
	bool SecuredExecution();
	bool MakeItDeadInternal(std::stack<std::wstring> &In);
	
	virtual bool ModeAll() { return Vars.mode_all; }
	virtual bool ModeLoop() { return Vars.mode_loop; }
	virtual bool ModeBlank() { return Vars.mode_blank; }
public:
	void MakeItDead(std::stack<std::wstring> &In);
	Controller();
};
															
#endif //CONTROLLER_H