#include "Extras.h"
#include "Common.h"
#include "Killers.h"
#include "ProcessUsage.h"
#include "Controller.h"
#include <stdio.h>
#include <iostream>
#include <functional>
#include <memory>
#include <limits>	//numeric_limits
#include <conio.h>

#define MUTEX_NAME		L"MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

extern pWcoutMessageBox fnWcoutMessageBox;
extern pEnableWcout fnEnableWcout;

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
void Controller<ProcessesPolicy, KillersPolicy>::DiscardedParam(const std::wstring &sw_param)
{
	std::wcerr<<L"Warning: "<<sw_param<<L" parameter discarded!"<<std::endl;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::IgnoredSwitch(const std::wstring &sw)
{
	std::wcerr<<L"Warning: "<<sw<<L" switch will be ignored!"<<std::endl;
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
DWORD Controller<ProcessesPolicy, KillersPolicy>::IsBOM(DWORD bom)
{
	//4-byte BOMs
	if (bom==0x33953184||		//GB-18030
		bom==0x736673DD||		//UTF-EBCDIC
		bom==0x38762F2B||		//UTF-7
		bom==0x39762F2B||		//UTF-7
		bom==0x2B762F2B||		//UTF-7
		bom==0x2F762F2B||		//UTF-7
		bom==0x0000FEFF||		//UTF-32 LE
		bom==0xFFFE0000)		//UTF-32 BE
		return bom;
		
	//3-byte BOMs
	bom&=0xFFFFFF;
	if (bom==0xBFBBEF||			//UTF-8
		bom==0x28EEFB||			//BOCU-1
		bom==0x4C64F7||			//UTF-1
		bom==0xFFFE0E)			//SCSU
		return bom;
		
	//2-byte BOMs
	bom&=0xFFFF;
	if (bom==0xFEFF||			//UTF-16 LE
		bom==0xFFFE)			//UTF-16 BE
		return bom;

	return 0x0;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath, CmdMode param_cmd_mode)
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
		
		if (ReadFile(h_cmdfile, &bom, 4, &buf_len, NULL)) {
			//This function requires wchar_t-NULL-terminated (L'\0') array, no matter what actual coding is
			//It converts BYTE array to NULL-terminated wchar_t array
			std::function<void(BYTE* &cmdline)> fnConvertCmdline;
			
			bom=IsBOM(bom);
			
			if (bom==0xFEFF||				//UTF16 LE (ordinary Windows Unicode)
				//Use this encoding if BOM is absent and CMDCP_UTF16 set
				(!bom&&param_cmd_mode==CMDCP_UTF16)) {
				fnConvertCmdline=[](BYTE* &cmdline){
					//Nothing to be done here, cmdline is already NULL-terminated wchar_t (which is UTF16 LE on Windows) array, just type cast it
				};
				bom_sz=bom?2:0;
			} else if (bom==0xFFFE) {		//UTF16 BE
				fnConvertCmdline=[](BYTE* &cmdline){
					//Already NULL-terminated, just need to reverse UTF16 BE BYTE pairs to make it wchar_t (which is UTF16 LE on Windows) array
					wchar_t* wcmdline=(wchar_t*)cmdline;
					while (*wcmdline) {
						*wcmdline=(*wcmdline>>8&0xFF)|*wcmdline<<8;	//Signedness of wchar_t is implementation defined so don't expect right shift to be padded with zeroes
						wcmdline++;
					}
				};
				bom_sz=2;
			} else if (bom==0xBFBBEF||		//UTF8
				//Use this encoding if BOM is absent and CMDCP_UTF8 set
				(!bom&&param_cmd_mode==CMDCP_UTF8)) {
				fnConvertCmdline=[](BYTE* &cmdline){
					//Need to convert from UTF8 to wchar_t
					if (int wchars_num=MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdline, -1, NULL, 0)) {
						BYTE *wcmdline=new BYTE[wchars_num*sizeof(wchar_t)];
						if (MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdline, -1, (wchar_t*)wcmdline, wchars_num)) {
							delete[] cmdline;
							cmdline=wcmdline;
							return;
						}
						delete[] wcmdline;
					}
					*(wchar_t*)cmdline=L'\0';
				};
				bom_sz=bom?3:0;
			} else if (bom) {				//UTF-32, UTF-7, UTF-1, UTF-EBCDIC, SCSU, BOCU-1, GB-18030
				//Unsupported encodings
				//These encodings are rarely used on Windows for plain text file encoding (if used at all)
				CloseHandle(h_cmdfile);
				std::wcerr<<L"Warning: \""<<arg_cmdpath<<L"\" have unsupported encoding!"<<std::endl;
				return;
			} else {						//ANSI
				//BOM is not required for UTF-8 and rarely used on systems for which UTF-8 is native (which Windows is not)
				//Sometimes BOM can be missing from encodings where it should be (e.g. redirecting wcout to file produces UTF-16 LE w/o BOM)
				//Windows Notepad always saves non-ANSI encoded files with BOM
				//If BOM is missing from UTF-8 or UTF-16, param_cmd_mode can be set accordingly to force these encodings (these cases are dealt with in the code above)
				//Otherwise missing BOM will be treated as ANSI encoding
				fnConvertCmdline=[](BYTE* &cmdline){
					//Need to convert from ANSI to wchar_t
					if (int wchars_num=MultiByteToWideChar(CP_ACP, 0, (const char*)cmdline, -1, NULL, 0)) {
						BYTE *wcmdline=new BYTE[wchars_num*sizeof(wchar_t)];
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
				//+sizeof(wchar_t) bytes for the wchar_t-NULL terminator (ConvertCmdline requirement)
				BYTE *cmdfile_buf=new BYTE[buf_len+sizeof(wchar_t)];
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
	//By C++ standard it is guaranteed that false is converted to 0 when type-casted to int
	//So any non-bool variables in param_first and param_second unions will be assigned 0
	//By design none of these union variables are greater in size than param_first/param_second so assignment won't leave any bytes unaffected
	ctrl_vars.param_first=false;
	ctrl_vars.param_second=false;
	ctrl_vars.args.clear();
}

template <typename ProcessesPolicy, typename KillersPolicy>	
bool Controller<ProcessesPolicy, KillersPolicy>::IsDone(bool sw_res)
{
	if (ModeIgnore())
		return false;
	else if (ModeNegate())
		return !sw_res;
	else
		return sw_res;
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
	} else if (!top_rule.compare(L"+n")) {
		ctrl_vars.mode_negate=true;
	} else if (!top_rule.compare(L"-n")) {
		ctrl_vars.mode_negate=false;
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
	} else if (!top_rule.compare(L"+m")) {
		ctrl_vars.mode_mute=true;
		if (fnEnableWcout) fnEnableWcout(false);
	} else if (!top_rule.compare(L"-m")) {
		ctrl_vars.mode_mute=false;
		if (fnEnableWcout) fnEnableWcout(true);
	} else if (!top_rule.compare(L"+l")) {
		ctrl_vars.mode_loop=true;
	} else if (!top_rule.compare(L"-l")) {
		ctrl_vars.mode_loop=false;
	} else if (!top_rule.compare(L"+b")) {
		ctrl_vars.mode_blacklist=true;
	} else if (!top_rule.compare(L"-b")) {
		ctrl_vars.mode_blacklist=false;
	} else if (!top_rule.compare(L"+w")) {
		ctrl_vars.mode_whitelist=true;
	} else if (!top_rule.compare(L"-w")) {
		ctrl_vars.mode_whitelist=false;
#if DEBUG>=1
	} else if (!top_rule.compare(L"/lst:debug")) {
		if (ctrl_vars.param_lst_mode==LstMode::LST_SHOW)
			ctrl_vars.param_lst_mode=LstMode::LST_DEBUG;
		else
			DiscardedParam(top_rule);
#endif
	} else if (!top_rule.compare(L"/lst:clrmask")) {
		if (ctrl_vars.param_lst_mode==LstMode::LST_SHOW)
			ctrl_vars.param_lst_mode=LstMode::CLR_MASK;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst:invmask")) {
		if (ctrl_vars.param_lst_mode==LstMode::LST_SHOW)
			ctrl_vars.param_lst_mode=LstMode::INV_MASK;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst")) {
		ManageProcessList(ctrl_vars.param_lst_mode);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/bpp")) {
		NoArgsAllowed(top_rule);
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/sec")) {
		//Not affected by ignore, loop and negate modes
		NoArgsAllowed(top_rule);
		done=SecuredExecution();
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/cmd:utf8")) {
		if (ctrl_vars.param_cmd_mode==CMDCP_AUTO)
			ctrl_vars.param_cmd_mode=CMDCP_UTF8;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/cmd:utf16")) {
		if (ctrl_vars.param_cmd_mode==CMDCP_AUTO)
			ctrl_vars.param_cmd_mode=CMDCP_UTF16;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/cmd")) {
		ProcessCmdFile(rules, ctrl_vars.args.c_str(), ctrl_vars.param_cmd_mode);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/hlp")) {
		//Usable only on first run
		if (ctrl_vars.first_run) {
			PrintUsage();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			IgnoredSwitch(top_rule);
	} else if (!top_rule.compare(L"/ver")) {
		//Usable only on first run
		if (ctrl_vars.first_run) {
			PrintVersion();
			done=true;
#ifdef HIDDEN
			ctrl_vars.mode_verbose=true;
#endif
		} else
			IgnoredSwitch(top_rule);
	} else if (!top_rule.compare(L"/cpu")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByCpu());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pth:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/pth")) {
		done=IsDone(KillByPth(ctrl_vars.param_full, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/mod:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/mod")) {
		done=IsDone(KillByMod(ctrl_vars.param_full, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pid")) {
		done=IsDone(KillByPid(ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/d3d:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/d3d")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByD3d(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/ogl:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/ogl")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByOgl(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/gld:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/gld")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByGld(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/inr:plus")) {
		ctrl_vars.param_plus=true;
	} else if (!top_rule.compare(L"/inr")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByInr(ctrl_vars.param_plus));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fsc:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fsc:primary")) {
		ctrl_vars.param_primary=true;
	} else if (!top_rule.compare(L"/fsc")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByFsc(ctrl_vars.param_anywnd, ctrl_vars.param_primary));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fgd:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fgd")) {
		NoArgsAllowed(top_rule);
		done=IsDone(KillByFgd(ctrl_vars.param_anywnd));
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
	return !done;
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
