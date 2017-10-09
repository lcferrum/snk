#ifndef KILLERS_H
#define KILLERS_H

#include "ProcessUsage.h"
#include <string>
#include <vector>
#include <windows.h>

class Killers: virtual protected ProcessesCrossBase {
private:
	void KillProcess(DWORD PID, const std::wstring &name);
	void PrintCommonKillPrefix();
	void PrintCommonWildcardInfix(const wchar_t* arg_wcard, const wchar_t* delim=L";");
	bool CheckStringFileInfo(const wchar_t* fpath, const wchar_t** item_str, const wchar_t** desc_str);
	bool CheckModListNames(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, bool full, const wchar_t* wcard);
	bool CheckModListDescriptions(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, const wchar_t** item_str, const wchar_t** desc_str);
	bool CheckProcessUserName(ULONG_PTR PID, const wchar_t* wcard, bool incl_domain);
	bool PidListPrepare(const wchar_t* pid_list, std::vector<ULONG_PTR> &uptr_array);
	bool PidListCompare(std::vector<ULONG_PTR> &uptr_array, ULONG_PTR pid);
	bool KillParentPid();
	bool KillPidsInArray(const wchar_t* arg_parray);
	
	static bool IsTaskWindow(HWND hwnd);
	static bool WithinRect(const RECT &outer, const RECT &inner);
	static BOOL CALLBACK EnumWndInr(HWND hwnd, LPARAM lParam);
	static BOOL CALLBACK EnumWndWnd(HWND hwnd, LPARAM lParam);
	static BOOL CALLBACK EnumWndFsc(HWND hwnd, LPARAM lParam);
	static BOOL CALLBACK EnumWndClose(HWND hwnd, LPARAM lParam);
	
	virtual bool ModeBlank()=0;
	virtual bool ModeRecent()=0;
	virtual bool ModeClose()=0;
	virtual bool ModeAll()=0;
	virtual bool ModeLoop()=0;
	virtual bool ModeBlacklist()=0;
	virtual bool ModeWhitelist()=0;
protected:	
	//Kills process with highest cpu load (or whatever actual sorting was)
	bool KillByCpu();
	
	//Kills process with highest cpu load which path matches one of wildcars (case-insensitive, with globbing)
	//arg_wcard - wildcards to match (delimeted by semicolon)
	//If param_full - uses full path, otherwise uses just name
	bool KillByPth(bool param_full, const wchar_t* arg_wcard);
	
	//Kills process with highest cpu load that has module which path matches one of wildcars (case-insensitive, with globbing)
	//arg_wcard - wildcards to match (delimeted by semicolon)
	//If param_full - uses full path, otherwise uses just name
	bool KillByMod(bool param_full, const wchar_t* arg_wcard);
	
	//Kills process with highest cpu load which PID belongs to PID array
	//PIDs are decimal (no prefix), hexadecimal ("0x"/"0X" prefix) or octal ("0" prefix) unsigned integers
	//arg_parray - array of PIDs to match (delimeted by comma or semicolon, can include descending or ascending ranges)
	//If param_parent - ignores arg_parray and uses parent process PID instead
	bool KillByPid(bool param_parent, const wchar_t* arg_parray);
	
	//Kills process with highest cpu load that uses DirectX (Direct3D)
	//If param_simple - uses process modules names to find DirectX process
	//If not param_simple - uses description of modules
	bool KillByD3d(bool param_simple);
	
	//Kills process with highest cpu load that uses OpenGL
	//If param_simple - uses process modules names to find OpenGL process
	//If not param_simple - uses description of modules
	bool KillByOgl(bool param_simple);
	
	//Kills process with highest cpu load that uses Glide (3Dfx)
	//If param_simple - uses process modules names to find Glide process
	//If not param_simple - uses description of modules
	bool KillByGld(bool param_simple);
	
	//Kills process with highest cpu load that doesn't respond (Is Not Responding)
	//By default checks applications with IsHungAppWindow()
	//If param_plus - also checks applications with SendMessageTimeout() and 5 sec timeout
	bool KillByInr(bool param_plus);
	
	//Kills process with highest cpu load that is running in fullscreen
	//Works with multi-monitor setups
	//By default only exclusive fullscreen and borderless windowed processes are checked
	//If param_anywnd - checks processes with any window
	//If param_primary - checks only windows that belong to primary display
	//If param_strict - only fullscreen windows with largest are checked
	bool KillByFsc(bool param_anywnd, bool param_primary, bool param_strict);
	
	//Kills process with highest cpu load which window is in foreground
	//By default filters out windows that doesn't show in task bar
	//If param_anywnd - doesn't apply task bar filter
	bool KillByFgd(bool param_anywnd);
	
	//Kills process with highest cpu load which window title matches wildcard (case-insensitive, with globbing)
	//arg_wcard - wildcard to match
	//If param_anywnd - doesn't apply task bar filter, but window has to be visible
	bool KillByWnd(bool param_anywnd, const wchar_t* arg_wcard);
	
	//Kills process with highest cpu load which user name matches one of wildcards (case-insensitive, with globbing)
	//arg_wcard - wildcards to match (delimeted by comma or semicolon)
	//If param_full - uses full user name (DOMAIN\NAME), otherwise uses just name (NAME)
	bool KillByUsr(bool param_full, const wchar_t* arg_wcard);
	
	//Kills process with highest cpu and highest memory usage
	//arg_maxmem - if supplied, kills processes that have memory usage strictly greater than arg_maxmem (decimal unsigned integer, in KB)
	//If param_vm - uses virtual memory private bytes metric, otherwise uses physical memory working set metric
	bool KillByMem(bool param_vm, const wchar_t* arg_maxmem);
public:
	Killers();
};
															
#endif //KILLERS_H