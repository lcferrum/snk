#include "Externs.h"
#include "Common.h"
#include "Killers.h"
#include "ProcessUsage.h"
#include "Controller.h"
#include <conio.h>
#include <stdio.h>
#include <iostream>
#include <algorithm> 
#include <functional>
#include <limits>	//numeric_limits

#define MUTEX_NAME		L"MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

template <typename ProcessesPolicy, typename KillersPolicy>	
Controller<ProcessesPolicy, KillersPolicy>::Controller():
	ProcessesPolicy(), KillersPolicy(), ctrl_vars{true}, args_stack(), rlist(), sec_mutex(NULL)
{}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::NoArgsAllowed(const std::wstring &sw) 
{
	if (!ctrl_vars.args.empty())
		std::wcerr<<L"Warning: switch "<<sw<<L" doesn't allow arguments: \""<<ctrl_vars.args<<L"\"!"<<std::endl;
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
bool Controller<ProcessesPolicy, KillersPolicy>::WaitForUserInput(bool do_restart)
{
	if (do_restart) {
#ifdef HIDDEN
		std::wcout<<L"Press OK to restart killed apps or CANCEL to finish..."<<std::endl;
		do_restart=Win32WcostreamMessageBox(true);
#else
		DWORD conmode;
		if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &conmode)) {
			//ANSI input is ok for this case
			//0x1B is ESC
			std::wcout<<L"Press ENTER to restart killed apps or ESC to finish..."<<std::flush;
			char command;
			do command=tolower(_getch()); while (command!='\r'&&command!=0x1B&&command!=EOF);
			do_restart=command=='\r';
			std::wcout<<std::endl;
		} else {
			//For non-console input allow only ENTER because it becomes ugly when trying to support anything else
			std::wcout<<L"Killed apps will be restarted. When finished, press ENTER..."<<std::flush;
			std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');	//Needs defined NOMINMAX
		}
#endif
		return do_restart;
	} else {
#ifdef HIDDEN
		std::wcout<<L"When finished, press OK..."<<std::endl;
		Win32WcostreamMessageBox(false);
#else
		std::wcout<<L"When finished, press ENTER..."<<std::flush;
		std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');	//Needs defined NOMINMAX
#endif
		return false;
	}
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
bool Controller<ProcessesPolicy, KillersPolicy>::ProcessCmdFile(std::stack<std::wstring> &rules, const wchar_t* arg_cmdpath, CmdMode param_cmd_mode)
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
	
	//CommandLineToArgvW has an interesting behaviour of how it parses the very first argument
	//Without going into details - double quotes handling algorithm is different from the rest of arguments
	//If you want to use double quotes to keep spaces in the first argument - the very first character of input string should be double quote
	//E.g.: string ["argument one"] works as expected but [argument" one"] will produce two arguments instead - [argument"] and [one"]
	//So you can't use something like [/pth:full="C:\Program Files\program.exe"] for the first argument
	//But you can use ["/pth:full=C:\Program Files\program.exe"] which looks ugly but does the work	
	//In the end it's better to prepend input string with whitespace - that will simply produce empty first argument
	//Empty arguments are ignored by MakeRulesFromArgv so everything will look clean and from now on parsing will work as expected
	//That's why each read file is prepended with '\n' in the following algorithm - '\n' will be converted to space before passing file contents to CommandLineToArgvW
	
	HANDLE h_cmdfile;
	bool success=false;		//Current status of cmdfile read
	if ((h_cmdfile=CreateFile(arg_cmdpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, NULL))!=INVALID_HANDLE_VALUE) {
		DWORD cmdfile_len, cmdfile_len_high;
		if ((cmdfile_len=GetFileSize(h_cmdfile, &cmdfile_len_high))!=INVALID_FILE_SIZE&&cmdfile_len&&!cmdfile_len_high) {	//For the sake of simplicity only files under 4GB are supported
			if (HANDLE h_cmdfilemap=CreateFileMapping(h_cmdfile, NULL, PAGE_READONLY, 0, 0, NULL)) {	//CreateFileMapping fails with ERROR_FILE_INVALID if file is empty (zero length)
				if (void* cmdfile_mem=MapViewOfFile(h_cmdfilemap, FILE_MAP_READ, 0, 0, 0)) {
					DWORD bom=0;				//Initialize BOM with 0 so unread bytes won't be filled with garbage
					wchar_t* wcmdfile_buf=NULL;	//Buffer that receives converted cmdfile, ready to read by CommandLineToArgvW
					DWORD wcmdfile_len;			//Length of wcmdfile_buf in characters
					memcpy(&bom, cmdfile_mem, std::min((decltype(cmdfile_len))sizeof(bom), cmdfile_len));
					bom=IsBOM(bom);
					
					//Conversions below assume that wchar_t represents UTF16 LE so is 2 bytes in length
					//On Windows wchar_t is indeed UTF16 LE (even for versions of NT that run on bi-endian platforms)
					//But by C++ standard wchar_t is implementation defined so, just in case, test that we really dealing with 2 byte wchar_t
					static_assert(sizeof(wchar_t)==2, L"sizeof(wchar_t) should be exactly 2 bytes");
					if (bom==0xFEFF||(!bom&&param_cmd_mode==CMDCP_UTF16)) {	//UTF16 LE (ordinary Windows Unicode), use this encoding if BOM is absent and CMDCP_UTF16 set
						//Nothing to be done here, cmdline is already wchar_t (which is UTF16 LE on Windows) array
						//Just terminate it with NULL and pad with '\n'
						cmdfile_len-=bom?2:0;				//Compensating for bom
						cmdfile_mem=(BYTE*)cmdfile_mem+(bom?2:0);
						if (!(cmdfile_len%2)) {	//Make sure that cmdfile length is even, because otherwise it can't be UTF16
							wcmdfile_len=cmdfile_len/2+2;	//+2 is for terminating NULL and leading '\n'
							wcmdfile_buf=new wchar_t[wcmdfile_len];	
							memcpy(wcmdfile_buf+1, cmdfile_mem, cmdfile_len);
							success=true;
						} else
							std::wcerr<<L"Warning: file \""<<arg_cmdpath<<L"\" doesn't appear to be UTF16 LE encoded!"<<std::endl;
					} else if (bom==0xFFFE) {		//UTF16 BE
						//Need to reverse UTF16 BE BYTE pairs to make it wchar_t (which is UTF16 LE on Windows) array
						cmdfile_len-=2;					//Compensating for bom
						cmdfile_mem=(BYTE*)cmdfile_mem+2;
						if (!(cmdfile_len%2)) {	//Make sure that cmdfile length is even, because otherwise it can't be UTF16
							wcmdfile_len=cmdfile_len/2+2;	//+2 is for terminating NULL and leading '\n'
							wcmdfile_buf=new wchar_t[wcmdfile_len];	
							WORD *dst_wbuf=(WORD*)(wcmdfile_buf+1);
							WORD *src_wbuf=(WORD*)cmdfile_mem;
							for (DWORD src_pos=0; src_pos<cmdfile_len/2; src_pos++)
								dst_wbuf[src_pos]=(src_wbuf[src_pos]>>8)|((src_wbuf[src_pos]&0xFF)<<8);	//Unsigned right shift is logical one (padded with 0) by C++ standard
							success=true;
						} else
							std::wcerr<<L"Warning: file \""<<arg_cmdpath<<L"\" doesn't appear to be UTF16 BE encoded!"<<std::endl;
					} else if (bom==0xBFBBEF||(!bom&&param_cmd_mode==CMDCP_UTF8)) {	//UTF8, use this encoding if BOM is absent and CMDCP_UTF8 set
						//Need to convert from UTF8 to wchar_t
						cmdfile_len-=bom?3:0;					//Compensating for bom
						cmdfile_mem=(BYTE*)cmdfile_mem+(bom?3:0);
						if ((wcmdfile_len=MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdfile_mem, cmdfile_len, NULL, 0))) {
							wcmdfile_buf=new wchar_t[wcmdfile_len+2];	//+2 is for terminating NULL and leading '\n'
							if (MultiByteToWideChar(CP_UTF8, 0, (const char*)cmdfile_mem, cmdfile_len, wcmdfile_buf+1, wcmdfile_len)) {
								wcmdfile_len+=2;
								success=true;
							}
						}
						if (!success)
							std::wcerr<<L"Warning: error while converting \""<<arg_cmdpath<<L"\" from UTF8 to UTF16 LE!"<<std::endl;
					} else if (bom) {				//UTF-32, UTF-7, UTF-1, UTF-EBCDIC, SCSU, BOCU-1, GB-18030
						//Unsupported encodings
						//These encodings are rarely used on Windows for plain text file encoding (if used at all)
						std::wcerr<<L"Warning: file \""<<arg_cmdpath<<L"\" has unsupported encoding!"<<std::endl;
					} else {						//ANSI
						//BOM is not required for UTF-8 and rarely used on systems for which UTF-8 is native (which Windows is not)
						//Sometimes BOM can be missing from encodings where it should be (e.g. redirecting wcout to file produces UTF-16 LE w/o BOM)
						//Windows Notepad always saves non-ANSI encoded files with BOM
						//If BOM is missing from UTF-8 or UTF-16, param_cmd_mode can be set accordingly to force these encodings (these cases are dealt with in the code above)
						//Otherwise missing BOM will be treated as ANSI encoding
						if ((wcmdfile_len=MultiByteToWideChar(CP_ACP, 0, (const char*)cmdfile_mem, cmdfile_len, NULL, 0))) {
							wcmdfile_buf=new wchar_t[wcmdfile_len+2];	//+2 is for terminating NULL and leading '\n'
							if (MultiByteToWideChar(CP_ACP, 0, (const char*)cmdfile_mem, cmdfile_len, wcmdfile_buf+1, wcmdfile_len)) {
								wcmdfile_len+=2;
								success=true;
							}
						}
						if (!success)
							std::wcerr<<L"Warning: error while converting \""<<arg_cmdpath<<L"\" from ANSI to UTF16 LE!"<<std::endl;
					}
					
					if (success) {
						wcmdfile_buf[0]=L'\n';
						wcmdfile_buf[wcmdfile_len-1]=L'\0';
						
						//Changing all \n and \r symbols to spaces
						//If new line starts with '#' - change all of it into spaces
						wchar_t* wcmdfile_cnv=wcmdfile_buf;
						bool hashtag=false;
						bool newline=false;
						while (*wcmdfile_cnv) {
							if (*wcmdfile_cnv==L'\r'||*wcmdfile_cnv==L'\n') {
								hashtag=false;
								newline=true;
								*wcmdfile_cnv=L' ';
							} else {
								if (newline&&*wcmdfile_cnv==L'#') {
									hashtag=true;
									*wcmdfile_cnv=L' ';
								} else if (hashtag) {
									*wcmdfile_cnv=L' ';
								}
								newline=false;
							}
							wcmdfile_cnv++;
						}
						
						//Getting ARGV/ARGC and pushing them to rules stack
						wchar_t** cmd_argv;
						int cmd_argc;
#if DEBUG>=3
						std::wcerr<<L"" __FILE__ ":ProcessCmdFile:"<<__LINE__<<L": Command file buffer = \""<<wcmdfile_buf<<"\""<<std::endl;
#endif
						if ((cmd_argv=CommandLineToArgvW(wcmdfile_buf, &cmd_argc))) {
							MakeRulesFromArgv(cmd_argc, cmd_argv, rules, 0);
							if (!rules.size()) {
								std::wcerr<<L"Warning: file \""<<arg_cmdpath<<L"\" doesn't contain any commands!"<<std::endl;
								success=false;
							}
							LocalFree(cmd_argv);
						}
					}
					
					delete[] wcmdfile_buf;
					UnmapViewOfFile(cmdfile_mem);
				}
				
				CloseHandle(h_cmdfilemap);
			} else 
				std::wcerr<<L"Warning: error while reading file \""<<arg_cmdpath<<L"\"!"<<std::endl;
		} else
			std::wcerr<<L"Warning: file \""<<arg_cmdpath<<L"\" is empty, too large (>4GB) or of unknown size!"<<std::endl;
	
		CloseHandle(h_cmdfile);
	} else
		std::wcerr<<L"Warning: failed to open \""<<arg_cmdpath<<L"\" for command processing!"<<std::endl;
	
	return success;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::ClearParamsAndArgs()
{
	//By C++ standard it is guaranteed that false is converted to 0 when type-casted to int
	//So any non-bool variables in param_first and param_second unions will be assigned 0
	//By design none of these union variables are greater in size than param_first/param_second so assignment won't leave any bytes unaffected
	ctrl_vars.param_first=false;
	ctrl_vars.param_second=false;
	ctrl_vars.param_third=false;
	ctrl_vars.args.clear();
}

template <typename ProcessesPolicy, typename KillersPolicy>	
std::wstring Controller<ProcessesPolicy, KillersPolicy>::ExpandEnvironmentStringsWrapper(const std::wstring &args)
{
	wchar_t dummy_buf;

	//Documentation says that lpDst parameter is optional but Win 95 version of this function actually fails if lpDst is NULL
	//So using dummy buffer to get needed buffer length (function returns length in characters including terminating NULL)
	//If returned length is 0 - it is an error
	if (DWORD buf_len=ExpandEnvironmentStrings(args.c_str(), &dummy_buf, 0)) {
		wchar_t string_buf[buf_len];
		//Ensuring that returned length is expected length
		if (ExpandEnvironmentStrings(args.c_str(), string_buf, buf_len)<=buf_len) 
			return string_buf;
	}
	
	return args;
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
void Controller<ProcessesPolicy, KillersPolicy>::ProcessRestartList(bool do_restart)
{
	//On Win Vista+ w/ UAC enabled application running under admin account by default will run with "limited user" rights if not asked otherwise (rights "elevation")
	//Interesting thing is that option to run with administrator privileges is available also to non-admin accounts
	//But here this results in "run as" dialog because you can't "elevate" rights for non-admin account
	//In Task Scheduler option to "run with highest privileges" will work only with admin accounts and result in task running with "elevated" rights
	//On non-admin accounts this will do nothing - task won't be run under admin account, and current non-admin account rights won't be "elevated"

	for (const RestartProcessItem &rprc_item: rlist) {
		if (do_restart)
			ResumeThread(rprc_item.trd_handle);
		else
			TerminateProcess(rprc_item.prc_handle, ERROR_ACCESS_DENIED);
		CloseHandle(rprc_item.prc_handle);
		CloseHandle(rprc_item.trd_handle);
	}
}

template <typename ProcessesPolicy, typename KillersPolicy>	
typename Controller<ProcessesPolicy, KillersPolicy>::MIDStatus Controller<ProcessesPolicy, KillersPolicy>::MakeItDeadInternal(std::stack<std::wstring> &rules)
{	
	if (rules.empty()) return MID_EMPTY;
	
	bool done=false;
	std::wstring top_rule=std::move(rules.top());
	rules.pop();
	
	if (!top_rule.compare(L"+t")) {
		ctrl_vars.mode_blank=true;
	} else if (!top_rule.compare(L"-t")) {
		ctrl_vars.mode_blank=false;
	} else if (!top_rule.compare(L"+c")) {
		ctrl_vars.mode_close=true;
	} else if (!top_rule.compare(L"-c")) {
		ctrl_vars.mode_close=false;
	} else if (!top_rule.compare(L"+e")) {
		ctrl_vars.mode_env=true;
	} else if (!top_rule.compare(L"-e")) {
		ctrl_vars.mode_env=false;
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
	} else if (!top_rule.compare(L"+s")) {
		if (ctrl_vars.mode_recent==false) {
			SortByRecentlyCreated();
			ctrl_vars.mode_recent=true;
		}
	} else if (!top_rule.compare(L"-s")) {
		if (ctrl_vars.mode_recent==true) {
			SortByCpuUsage();
			ctrl_vars.mode_recent=false;
		}
	} else if (!top_rule.compare(L"+m")) {
		ctrl_vars.mode_mute=true;
		Win32WcostreamEnabled(false);
	} else if (!top_rule.compare(L"-m")) {
		ctrl_vars.mode_mute=false;
		Win32WcostreamEnabled(true);
	} else if (!top_rule.compare(L"+l")) {
		ctrl_vars.mode_loop=true;
	} else if (!top_rule.compare(L"-l")) {
		ctrl_vars.mode_loop=false;
	} else if (!top_rule.compare(L"+r")) {
		ctrl_vars.mode_restart=true;
	} else if (!top_rule.compare(L"-r")) {
		ctrl_vars.mode_restart=false;
	} else if (!top_rule.compare(L"+b")) {
		ctrl_vars.mode_blacklist=true;
	} else if (!top_rule.compare(L"-b")) {
		ctrl_vars.mode_blacklist=false;
	} else if (!top_rule.compare(L"+w")) {
		ctrl_vars.mode_whitelist=true;
	} else if (!top_rule.compare(L"-w")) {
		ctrl_vars.mode_whitelist=false;
	} else if (!top_rule.compare(L"+f")) {
		ManageProcessList(LstPriMode::CAN_FFWD, LstSecMode::LST_DUNNO);
	} else if (!top_rule.compare(L"+p")) {
		ManageProcessList(LstPriMode::EX_PARENT, LstSecMode::LST_DUNNO);
#if DEBUG>=1
	} else if (!top_rule.compare(L"/lst:debug")) {
		if (ctrl_vars.param_lst_sec_mode==LstSecMode::LST_DUNNO)
			ctrl_vars.param_lst_sec_mode=LstSecMode::LST_DEBUG;
		else
			DiscardedParam(top_rule);
#endif
	} else if (!top_rule.compare(L"/lst:show")) {
		if (ctrl_vars.param_lst_sec_mode==LstSecMode::LST_DUNNO)
			ctrl_vars.param_lst_sec_mode=LstSecMode::LST_SHOW;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst:clrmask")) {
		if (ctrl_vars.param_lst_pri_mode==LstPriMode::SHOW_LIST)
			ctrl_vars.param_lst_pri_mode=LstPriMode::CLR_MASK;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst:invmask")) {
		if (ctrl_vars.param_lst_pri_mode==LstPriMode::SHOW_LIST)
			ctrl_vars.param_lst_pri_mode=LstPriMode::INV_MASK;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst:reset")) {
		if (ctrl_vars.param_lst_pri_mode==LstPriMode::SHOW_LIST)
			ctrl_vars.param_lst_pri_mode=LstPriMode::RST_CAN;
		else
			DiscardedParam(top_rule);
	} else if (!top_rule.compare(L"/lst")) {
		NoArgsAllowed(top_rule);
		//ManageProcessList is special - RequestPopulatedCAN is called inside this method
		ManageProcessList(ctrl_vars.param_lst_pri_mode, ctrl_vars.param_lst_sec_mode);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/end")) {
		NoArgsAllowed(top_rule);
		done=true;
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/bpp")) {
		NoArgsAllowed(top_rule);
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
		Sleep(750);
	} else if (!top_rule.compare(L"/prn")) {
		std::wcout<<ctrl_vars.args<<std::endl;
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/psh")) {
		args_stack.push(ctrl_vars.args);
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pop")) {
		std::wstring new_args;
		if (!args_stack.empty()) {
			new_args=std::move(args_stack.top());
			args_stack.pop();
		}
		if (ctrl_vars.args.empty()) {
			ClearParamsAndArgs();
			ctrl_vars.args=std::move(new_args);
		} else {
			SetEnvironmentVariable(ctrl_vars.args.c_str(), new_args.c_str());
			ClearParamsAndArgs();
		}
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
//cmd:sub is disabled till further versions
//	} else if (!top_rule.compare(L"/cmd:sub")) {
//		ctrl_vars.param_sub=true;
	} else if (!top_rule.compare(L"/cmd")) {
		if (ctrl_vars.param_sub) {
			std::stack<std::wstring> sub_rules;
			if (ProcessCmdFile(sub_rules, ctrl_vars.args.c_str(), ctrl_vars.param_cmd_mode)) {
				MIDStatus sub_ret;
				RequestPopulatedCAN();
				ClearParamsAndArgs();
				//Controller<ProcessesPolicy, KillersPolicy> sub_controller(*this); //We are using vector of unique_pointers - this is illegal now
				Controller<ProcessesPolicy, KillersPolicy> sub_controller;
				//ProcessesPolicy.Synchronize makes CAN members in sub_controller use some of the methods from local CAN members
				//It is done by passing reference for each local CAN member to corresponding sub_controller CAN member
				//That's why starting from Synchronize call till the end of the clause (when sub_controller will be destroyed) it's vital to not modify local CAN
				sub_controller.Synchronize(*this);
				//******** DO NOT MODIFY LOCAL CAN BEYOND THIS POINT ********
				while ((sub_ret=sub_controller.MakeItDeadInternal(sub_rules))==MID_NONE);
				args_stack=std::move(sub_controller.args_stack);
				if (sub_controller.sec_mutex!=sec_mutex) CloseHandle(sub_controller.sec_mutex);
				Win32WcostreamEnabled(!ctrl_vars.mode_mute);
				done=IsDone(sub_ret==MID_EMPTY);
				//*************** FREE TO MODIFY LOCAL CAN ******************
			} else {
				std::wcerr<<L"Warning: subroutine \""<<ctrl_vars.args<<"\" won't be called!"<<std::endl; 
				ClearParamsAndArgs();
			}
		} else {
			ProcessCmdFile(rules, ctrl_vars.args.c_str(), ctrl_vars.param_cmd_mode);
			ClearParamsAndArgs();
		}
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
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByCpu());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pth:strict")) {
		ctrl_vars.param_strict=true;
	} else if (!top_rule.compare(L"/pth:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/pth")) {
		RequestPopulatedCAN();
		done=IsDone(KillByPth(ctrl_vars.param_full, ctrl_vars.param_strict, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/mod:strict")) {
		ctrl_vars.param_strict=true;
	} else if (!top_rule.compare(L"/mod:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/mod")) {
		RequestPopulatedCAN();
		done=IsDone(KillByMod(ctrl_vars.param_full, ctrl_vars.param_strict, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/ofl:strict")) {
		ctrl_vars.param_strict=true;
	} else if (!top_rule.compare(L"/ofl:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/ofl")) {
		RequestPopulatedCAN();
		done=IsDone(KillByOfl(ctrl_vars.param_full, ctrl_vars.param_strict, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/wnd:class")) {
		ctrl_vars.param_class=true;
	} else if (!top_rule.compare(L"/wnd")) {
		RequestPopulatedCAN();
		done=IsDone(KillByWnd(ctrl_vars.param_class, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/pid")) {
		RequestPopulatedCAN();
		done=IsDone(KillByPid(ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/d3d:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/d3d")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByD3d(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/ogl:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/ogl")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByOgl(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/gld:simple")) {
		ctrl_vars.param_simple=true;
	} else if (!top_rule.compare(L"/gld")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByGld(ctrl_vars.param_simple));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/inr:plus")) {
		ctrl_vars.param_plus=true;
	} else if (!top_rule.compare(L"/inr")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByInr(ctrl_vars.param_plus));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fsc:anywnd")) {
		ctrl_vars.param_anywnd=true;
	} else if (!top_rule.compare(L"/fsc:primary")) {
		ctrl_vars.param_primary=true;
	} else if (!top_rule.compare(L"/fsc:strict")) {
		ctrl_vars.param_strict=true;
	} else if (!top_rule.compare(L"/fsc")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByFsc(ctrl_vars.param_anywnd, ctrl_vars.param_primary, ctrl_vars.param_strict));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/fgd")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByFgd());
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/usr:full")) {
		ctrl_vars.param_full=true;
	} else if (!top_rule.compare(L"/usr")) {
		RequestPopulatedCAN();
		done=IsDone(KillByUsr(ctrl_vars.param_full, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/mem:vm")) {
		ctrl_vars.param_vm=true;
	} else if (!top_rule.compare(L"/mem")) {
		RequestPopulatedCAN();
		done=IsDone(KillByMem(ctrl_vars.param_vm, ctrl_vars.args.c_str()));
		ClearParamsAndArgs();
	} else if (!top_rule.compare(L"/aim")) {
		RequestPopulatedCAN();
		NoArgsAllowed(top_rule);
		done=IsDone(KillByAim());
		ClearParamsAndArgs();
	} else if (top_rule.front()==L'=') {
		if (ctrl_vars.mode_env)
			ctrl_vars.args=ExpandEnvironmentStringsWrapper(top_rule.substr(1));
		else
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
					std::wcerr<<L"Warning: no arguments allowed for unknown switch: \""<<ctrl_vars.args<<L"\"!"<<std::endl;
					ctrl_vars.args.clear();
				}
			}
		}
	}

	ctrl_vars.first_run=false;
	return done?MID_HIT:MID_NONE;
}

template <typename ProcessesPolicy, typename KillersPolicy>	
void Controller<ProcessesPolicy, KillersPolicy>::MakeItDead(std::stack<std::wstring> &rules)
{
	while (MakeItDeadInternal(rules)==MID_NONE);
	
	bool do_restart=rlist.size();
	
	if (ctrl_vars.mode_verbose) do_restart=WaitForUserInput(do_restart);
	
	if (sec_mutex) { 
		CloseHandle(sec_mutex);
		sec_mutex=NULL;
	}
	
	Win32WcostreamEnabled(true);
	
	ctrl_vars={true};
	std::stack<std::wstring>().swap(args_stack);
	
	ManageProcessList(LstPriMode::RST_CAN, LstSecMode::LST_DUNNO);
	
	ProcessRestartList(do_restart);
	
	rlist.clear();
}

template class Controller<Processes, Killers>;
