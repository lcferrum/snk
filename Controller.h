#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stack>
#include <string>
#include <functional>
#include <windows.h>

template <typename ProcessesPolicy, typename KillersPolicy>	
class Controller: private ProcessesPolicy, private KillersPolicy {
	using ProcessesPolicy::AddPathToBlacklist;
	using ProcessesPolicy::AddPidToBlacklist;
	using ProcessesPolicy::ClearBlacklist;
	using ProcessesPolicy::SortByCpuUsage;
	using ProcessesPolicy::SortByRecentlyCreated;
	using KillersPolicy::KillByCpu;
	using KillersPolicy::KillByPth;
	using KillersPolicy::KillByMod;
	using KillersPolicy::KillByPid;
	using KillersPolicy::KillByD3d;
	using KillersPolicy::KillByOgl;
	using KillersPolicy::KillByGld;
	using KillersPolicy::KillByInr;
	using KillersPolicy::KillByFsc;
	using KillersPolicy::KillByFgd;
private:
	enum BlkMode:char {DEFAULT=0, FULL, PID, CLEAR};
	struct {
		bool first_run;
		bool mode_blank;
		bool mode_ignore;
		bool mode_all;
		bool mode_loop;
		bool mode_verbose;
		bool mode_recent;
		union {
			bool param_first;
			bool param_plus;
			BlkMode param_blk_mode;
			bool param_full;
			bool param_simple;
			bool param_anywnd;
		};
		union {
			bool param_second;
			bool param_primary;
		}; 
		std::wstring args;
	} ctrl_vars;
	
	HANDLE sec_mutex;
	
	void ClearParamsAndArgs();
	void NoArgsAllowed(const std::wstring &sw);
	void WaitForUserInput();
	bool SecuredExecution();
	void ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath);
	bool MakeItDeadInternal(std::stack<std::wstring> &rules);
	
	virtual bool ModeAll() { return ctrl_vars.mode_all; }
	virtual bool ModeLoop() { return ctrl_vars.mode_loop; }
	virtual bool ModeBlank() { return ctrl_vars.mode_blank; }
	virtual bool ModeRecent() { return ctrl_vars.mode_recent; }
public:
	void MakeItDead(std::stack<std::wstring> &rules);
	Controller();
};
															
#endif //CONTROLLER_H