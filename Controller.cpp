#include "Extras.h"
#include "Common.h"
#include "Killers.h"
#include "Controller.h"
#include <stdio.h>
#include <iostream>
#include <functional>
#include <memory>
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
		std::wcout<<L"Secured execution - this instance is already secured"<<std::endl;
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
			std::wcout<<L"Secured execution - another secured SnK instance is already running"<<std::endl;
			CloseHandle(sec_mutex);
			sec_mutex=NULL;
			return true;
		} else {
			std::wcout<<L"Secured execution - SnK instance secured"<<std::endl;
			return false;
		}
	}
	
	return false;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath)
{
	//No point in using wifstream
	//First, filename parameter for constructor and open() is const char*, not const wchar_t*
	//Second, it reads file BYTE by BYTE, putting every single BYTE in separate wchar_t (even if file is in Unicode)
	//Third, it completely ignores BOM treating it as set of ordinary characters
	//Win32 ReadFile is the way here
	
	//Word on limit of cmdline
	//Raymond Chen has a good blog post on this: https://blogs.msdn.microsoft.com/oldnewthing/20031210-00/?p=41553/
	//Short answer: "it depends"
	//Depends on the method which was used to launch a program
	//The best you can get is 32767 (char/wchar_t) using CreateProcess()
	//CommandLineToArgvW doesn't have any pre-set limitations
	//It is only limited by internal variable sizes for ARGV buffer size and number of arguments (ARGC) - all are INTs (signed 4-byte integers)
	//So any cmdline that won't cause overflow of mentioned vars is good to go
	
	HANDLE h_cmdfile;
	if ((h_cmdfile=CreateFile(arg_cmdpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, NULL))!=INVALID_HANDLE_VALUE) {
		DWORD buf_len, bom=0;	//Initialize BOM with 0 so unread bytes won't be filled with garbage
		BYTE bom_sz;
		
		if (ReadFile(h_cmdfile, &bom, 3, &buf_len, NULL)) {
			//This function requires 2-byte-NULL-terminated array, no matter what actual coding is
			//It converts BYTE array to NULL-terminated wchar_t array
			std::function<void(BYTE* &cmdline)> fnConvertCmdline;
			
			if ((bom&0xFFFF)==0xFEFF) {				//UTF16 LE (ordinary Windows Unicode)
				fnConvertCmdline=[](BYTE* &cmdline){
					//Nothing to be done here, cmdline is already NULL-terminated wchar_t array, just type cast it
				};
				bom_sz=2;
			} else if ((bom&0xFFFF)==0xFFFE) {		//UTF16 BE
				fnConvertCmdline=[](BYTE* &cmdline){
					//Already NULL-terminated, just need to reverse BYTE pairs to make it wchar_t array
					wchar_t* wcmdline=(wchar_t*)cmdline;
					while (*wcmdline) {
						*wcmdline=*wcmdline>>8&0xFF|*wcmdline<<8;	//Signedness of wchar_t is implementation defined so don't expect right shift to be padded with zeroes
						wcmdline++;
					}
				};
				bom_sz=2;
			} else if ((bom&0xFFFFFF)==0xBFBBEF) {	//UTF8
				fnConvertCmdline=[](BYTE* &cmdline){
					//Need to convert from UTF8 to wchar_t
					if (int wchars_num=MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdline, -1, NULL, 0)) {
						BYTE *wcmdline=new BYTE[wchars_num*2];
						if (MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdline, -1, (wchar_t*)wcmdline, wchars_num)) {
							delete[] cmdline;
							cmdline=wcmdline;
							return;
						}
						delete[] wcmdline;
					}
					*(wchar_t*)cmdline=L'\0';
				};
				bom_sz=3;
			} else {								//ANSI
				fnConvertCmdline=[](BYTE* &cmdline){
					//Need to convert from ANSI to wchar_t
					if (int wchars_num=MultiByteToWideChar(CP_ACP, 0, (const char*)cmdline, -1, NULL, 0)) {
						BYTE *wcmdline=new BYTE[wchars_num*2];
						if (MultiByteToWideChar(CP_ACP, 0, (const char*)cmdline, -1, (wchar_t*)wcmdline, wchars_num)) {
							delete[] cmdline;
							cmdline=wcmdline;
							return;
						}
						delete[] wcmdline;
					}
					*(wchar_t*)cmdline=L'\0';
				};
				bom_sz=0;
			}
			
			//Not using lpFileSizeHigh for GetFileSize()
			//Sorry guys, 4GB file limit - deal with it
			//Also don't bother processing zero-length files
			if (SetFilePointer(h_cmdfile, bom_sz, NULL, FILE_BEGIN)!=INVALID_SET_FILE_POINTER&&(buf_len=GetFileSize(h_cmdfile, NULL))!=INVALID_FILE_SIZE&&(buf_len-=bom_sz)) {
				//+2 bytes for the 2-byte NULL terminator (ConvertCmdline requirement)
				BYTE *cmdfile_buf=new BYTE[buf_len+2];
				//Yep, reading whole file in one pass
				if (ReadFile(h_cmdfile, cmdfile_buf, buf_len, &buf_len, NULL)) {
					*(wchar_t*)(cmdfile_buf+buf_len)=L'\0';
					fnConvertCmdline(cmdfile_buf);
					
					//Changing all \n and \r symbols to spaces
					wchar_t* wcmdfile_buf=(wchar_t*)cmdfile_buf;
					while (*wcmdfile_buf) {
						if (*wcmdfile_buf==L'\r'||*wcmdfile_buf==L'\n')
							*wcmdfile_buf=L' ';
						wcmdfile_buf++;
					}
					
					//Getting ARGV/ARGC and pushing them to rules stack
					wchar_t** cmd_argv;
					int cmd_argc;
					if ((cmd_argv=CommandLineToArgvW((wchar_t*)cmdfile_buf, &cmd_argc))) {
						MakeRulesFromArgv(cmd_argc, cmd_argv, rules, 0);
						LocalFree(cmd_argv);
					}
				}
				delete[] cmdfile_buf;
			}				
		}
		
		CloseHandle(h_cmdfile);
	} else
		std::wcerr<<L"Warning: failed to open \""<<arg_cmdpath<<L"\" for command processing!"<<std::endl;
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
	} else if (!top_rule.compare(L"+r")) {
		ctrl_vars.mode_recent=true;
		SortByRecentlyCreated();
	} else if (!top_rule.compare(L"-r")) {
		ctrl_vars.mode_recent=false;
		SortByCpuUsage();
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
	} else if (!top_rule.compare(L"/inr:plus")) {
		ctrl_vars.param_plus=true;
	} else if (!top_rule.compare(L"/inr")) {
		NoArgsAllowed(top_rule);
		done=KillByInr(ctrl_vars.param_plus);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fsc:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fsc:primary")) {
		ctrl_vars.param_primary=true;
	} else if (!top_rule.compare(L"/fsc")) {
		NoArgsAllowed(top_rule);
		done=KillByFsc(ctrl_vars.param_anywnd, ctrl_vars.param_primary);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fgd:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fgd")) {
		NoArgsAllowed(top_rule);
		done=KillByFgd(ctrl_vars.param_anywnd);
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
