#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stack>
#include <string>
#include <functional>
#include <windows.h>

template <typename ProcessesPolicy, typename KillersPolicy>	
class Controller: private ProcessesPolicy, private KillersPolicy {
	typedef typename ProcessesPolicy::LstPriMode LstPriMode;
	typedef typename ProcessesPolicy::LstSecMode LstSecMode;
	using ProcessesPolicy::ManageProcessList;
	using ProcessesPolicy::SortByCpuUsage;
	using ProcessesPolicy::SortByRecentlyCreated;
	using ProcessesPolicy::Synchronize;
	using ProcessesPolicy::RequestPopulatedCAN;
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
	using KillersPolicy::KillByWnd;
	using KillersPolicy::KillByUsr;
	using KillersPolicy::KillByMem;
	using KillersPolicy::KillByAim;
	using KillersPolicy::KillByOfl;
private:
	enum CmdMode:char {CMDCP_AUTO=0, CMDCP_UTF8, CMDCP_UTF16};	//Default mode should be 0 so variable can be reset by assigning it 0 or false
	enum MIDStatus:char {MID_HIT, MID_NONE, MID_EMPTY};
	typedef std::tuple<std::wstring, std::wstring, std::wstring, std::unique_ptr<BYTE[]>> RestartProcessTuple;
	
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
		bool mode_close;
		bool mode_env;
		bool mode_restart;
		//We should be able to change values of all variables in union by assigning something to it's largest member (should be param_first/param_second/param_third)
		//Don't expect bool (param_first/param_second/param_third type) to be the largest because size of bool is implementation defined 
		//Test with static_assert for other types to be smaller or equal in size
		union {						
			bool param_first;
			bool param_plus;
			static_assert(sizeof(LstPriMode)<=sizeof(bool), L"sizeof(ProcessesPolicy::LstPriMode) should be less or equal sizeof(bool)");
			LstPriMode param_lst_pri_mode;
			static_assert(sizeof(CmdMode)<=sizeof(bool), L"sizeof(Controller::CmdMode) should be less or equal sizeof(bool)");
			CmdMode param_cmd_mode;
			bool param_full;
			bool param_simple;
			bool param_anywnd;
			bool param_vm;
		};
		union {
			bool param_second;
			bool param_sub;
			bool param_primary;
			static_assert(sizeof(LstSecMode)<=sizeof(bool), L"sizeof(ProcessesPolicy::LstSecMode) should be less or equal sizeof(bool)");
			LstSecMode param_lst_sec_mode;
		};
		union {
			bool param_third;
			bool param_strict;
		}; 
		std::wstring args;
	} ctrl_vars;
	
	std::stack<std::wstring> args_stack;
	std::vector<RestartProcessTuple> rlist_normal;
	std::vector<RestartProcessTuple> rlist_elevated;
	
	//Windows will close mutex handle automatically when the process terminates
	HANDLE sec_mutex;
	
	void ClearParamsAndArgs();
	void NoArgsAllowed(const std::wstring &sw);
	void DiscardedParam(const std::wstring &sw_param);
	void IgnoredSwitch(const std::wstring &sw);
	bool WaitForUserInput(bool do_restart);
	bool SecuredExecution();
	DWORD IsBOM(DWORD bom);
	std::wstring ExpandEnvironmentStringsWrapper(const std::wstring &args);
	bool IsDone(bool sw_res);
	bool ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath, CmdMode param_cmd_mode);
	void DoRestart();
	void RestartProcess(const RestartProcessTuple &rprc);
	MIDStatus MakeItDeadInternal(std::stack<std::wstring> &rules);
	
	virtual bool ModeAll() { return ctrl_vars.mode_all||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeLoop() { return ctrl_vars.mode_loop||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeIgnore() { return ctrl_vars.mode_ignore||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeNegate() { return ctrl_vars.mode_negate; }
	virtual bool ModeBlank() { return ctrl_vars.mode_blank||ctrl_vars.mode_blacklist||ctrl_vars.mode_whitelist; }
	virtual bool ModeRecent() { return ctrl_vars.mode_recent; }
	virtual bool ModeRestart() { return ctrl_vars.mode_restart; }
	virtual bool ModeClose() { return ctrl_vars.mode_close; }
	virtual bool ModeBlacklist() { return ctrl_vars.mode_blacklist&&!ctrl_vars.mode_whitelist; }
	virtual bool ModeWhitelist() { return ctrl_vars.mode_whitelist&&!ctrl_vars.mode_blacklist; }
	
	virtual void RestartNormal(const std::wstring &path, std::wstring &&cmdline, std::wstring &&cwdpath, std::unique_ptr<BYTE[]> &&envblock) { rlist_normal.push_back(std::make_tuple(path, std::move(cmdline), std::move(cwdpath), std::move(envblock))); }
	virtual void RestartElevated(const std::wstring &path, std::wstring &&cmdline, std::wstring &&cwdpath, std::unique_ptr<BYTE[]> &&envblock) { rlist_elevated.push_back(std::make_tuple(path, std::move(cmdline), std::move(cwdpath), std::move(envblock))); }
public:
	void MakeItDead(std::stack<std::wstring> &rules);
	Controller();
};
															
#endif //CONTROLLER_H