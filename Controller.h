#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stack>
#include <string>
#include <functional>
#include <windows.h>

template <typename ProcessesPolicy, typename KillersPolicy>	
class Controller: private ProcessesPolicy, private KillersPolicy {
	typedef typename ProcessesPolicy::LstMode LstMode;
	using ProcessesPolicy::ManageProcessList;
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
	enum CmdMode:char {CMDCP_AUTO=0, CMDCP_UTF8, CMDCP_UTF16};	//Default mode should be 0 so variable can be reset by assigning it 0 or false
	
	struct {
		bool first_run;
		bool mode_blank;
		bool mode_ignore;
		bool mode_negate;
		bool mode_all;
		bool mode_loop;
		bool mode_verbose;
		bool mode_recent;
		bool mode_blacklist;
		bool mode_whitelist;
		bool mode_mute;
		//We should be able to change values of all variables in union by assigning something to it's largest member (should be param_first/param_second)
		//Don't expect bool (param_first/param_second type) to be the largest because size of bool is implementation defined 
		//Test with static_assert for other types to be smaller or equal in size
		union {						
			bool param_first;
			bool param_plus;
			static_assert(sizeof(LstMode)<=sizeof(bool), L"sizeof(ProcessesPolicy::LstMode) should be less or equal sizeof(bool)");
			LstMode param_lst_mode;
			static_assert(sizeof(CmdMode)<=sizeof(bool), L"sizeof(Controller::CmdMode) should be less or equal sizeof(bool)");
			CmdMode param_cmd_mode;
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
	void DiscardedParam(const std::wstring &sw_param);
	void IgnoredSwitch(const std::wstring &sw);
	void WaitForUserInput();
	bool SecuredExecution();
	DWORD IsBOM(DWORD bom);
	bool IsDone(bool sw_res);
	void ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath, CmdMode param_cmd_mode);
	bool MakeItDeadInternal(std::stack<std::wstring> &rules);
	
	virtual bool ModeAll() { return ctrl_vars.mode_all||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeLoop() { return ctrl_vars.mode_loop||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeIgnore() { return ctrl_vars.mode_ignore||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeNegate() { return ctrl_vars.mode_negate; }
	virtual bool ModeBlank() { return ctrl_vars.mode_blank||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeRecent() { return ctrl_vars.mode_recent; }
	virtual bool ModeBlacklist() { return ctrl_vars.mode_blacklist&&!ctrl_vars.mode_whitelist; }
	virtual bool ModeWhitelist() { return ctrl_vars.mode_whitelist&&!ctrl_vars.mode_blacklist; }
public:
	void MakeItDead(std::stack<std::wstring> &rules);
	Controller();
};
															
#endif //CONTROLLER_H