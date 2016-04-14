#ifndef KILLERS_H
#define KILLERS_H

#include "ProcessUsage.h"
#include <string>
#include <windows.h>

class Killers: virtual protected ProcessesCrossBase {
private:
	void KillProcess(DWORD PID, const std::wstring &name);
	bool CheckStringFileInfo(const wchar_t* fpath, const wchar_t** item_str, const wchar_t** desc_str);
	bool CheckName(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, bool full, const wchar_t* wcard);
	bool CheckDescription(const std::vector<std::pair<std::wstring, std::wstring>> &mlist, const wchar_t** item_str, const wchar_t** desc_str);
	
	static bool IsTaskWindow(HWND hwnd);
	static bool WithinRect(const RECT &outer, const RECT &inner);
	static BOOL CALLBACK EnumWndInr(HWND hwnd, LPARAM lParam);
	static BOOL CALLBACK EnumWndFsc(HWND hwnd, LPARAM lParam);
	
	virtual bool ModeBlank()=0;
protected:	
	enum InrMode:char {DEFAULT=0, MANUAL, VISTA};

	//Kills process with highest cpu load
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
	bool KillByPid(const wchar_t* arg_parray);
	
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
	//param_mode can be DEFAULT, MANUAL or VISTA
	//If DEFAULT - checks applications with IsHungAppWindow()
	//If MANUAL - checks applications with SendMessageTimeout() and 5 sec timeout
	//If VISTA - checks applications with NtUserHungWindowFromGhostWindow(), available starting from Vista
	bool KillByInr(InrMode param_mode);
	
	//Kills process with highest cpu load that is running in fullscreen
	//Works with multi-monitor setups
	//By default only exclusive fullscreen and borderless windowed processes are checked
	//If param_anywnd - checks processes with any window
	//If param_primary - checks only windows that belong to primary display
	bool KillByFsc(bool param_anywnd, bool param_primary);
	
	//Kills process with highest cpu load which window is in foreground
	bool KillByFgd();
public:
	Killers();
};
															
#endif //KILLERS_H