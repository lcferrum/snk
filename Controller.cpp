#include <stdio.h>
#include <iostream>
#include <limits>
#include <conio.h>
#include "Controller.h"

#define MUTEX_NAME			"Global\\MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

#ifdef HIDDEN
#include "ConRedirection.h"
#endifs

Controller::Controller():
	Killers(), ModeIgnore(false), ModeVerbose(false), sec_mutex(NULL)
{}

Controller::NoArgsAllowed(char* sw) 
{
	if (ArgsWcard) {
		cerr<<"Warning: switch "<<sw<<" doesn't allow arguments ("<<ArgsWcard<<")!"<<endl;
	}
}

Controller::WaitForUserInput()
{
#ifndef HIDDEN
	cout<<"Press ENTER to continue... "<<flush;
	cin.ignore(numeric_limits<streamsize>::max(), '\n');	//Needs defined NOMINMAX
#else
	cout<<"Press OK to continue... "<<endl;
	MessageBox(NULL, GetCoutBuf().c_str(), "Search and Kill", MB_ICONWARNING|MB_SETFOREGROUND);
#endif
}

Controller::SecuredExecution()
{
	SECURITY_ATTRIBUTES mutex_sa;
	PSECURITY_DESCRIPTOR p_mutex_sd;
	
	if (sec_mutex) {
		cout<<"Secured execution: this instance is already secured!"<<endl;
		return false;
	}
	
	if (!(p_mutex_sd=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) return false; 
	if (!InitializeSecurityDescriptor(p_mutex_sd, SECURITY_DESCRIPTOR_REVISION)) return false;
	if (!SetSecurityDescriptorDacl(p_mutex_sd, true, (PACL)NULL, true)) return false;
	mutex_sa.nLength=sizeof(SECURITY_ATTRIBUTES); 
	mutex_sa.lpSecurityDescriptor=p_mutex_sd;
	mutex_sa.bInheritHandle=false; 
	sec_mutex = CreateMutex(&mutex_sa, false, MUTEX_NAME);
	LocalFree(p_mutex_sd);
	
	if (sec_mutex) {
		if (GetLastError()==ERROR_ALREADY_EXISTS) {
			cout<<"Secured execution: another secured SnK instance is already running!"<<endl;
			CloseHandle(sec_mutex);
			sec_mutex=NULL;
			return true;
		} else {
			cout<<"Secured execution: SnK instance secured!"<<endl;
			return false;
		}
	}
	
	return false;
}

Controller::MakeItDeadInternal(stack<char*> &In)
{
	bool Done=false;

    if (In.empty()) return false;
	
	if (!strcmp("+t", In.top())) {
		ModeBlank=true;
	} else if (!strcmp("-t", In.top())) {
		ModeBlank=false;
	} else if (!strcmp("+i", In.top())) {
		ModeIgnore=true;
	} else if (!strcmp("-i", In.top())) {
		ModeIgnore=false;
	} else if (!strcmp("/cpu", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByCpu();
		ClearParamsAndArgs();
	} else if (!strcmp("+a", In.top())) {
		ModeAll=true;
	} else if (!strcmp("-a", In.top())) {
		ModeAll=false;
	} else if (!strcmp("+l", In.top())) {
		ModeLoop=true;
	} else if (!strcmp("-l", In.top())) {
		ModeLoop=false;
	} else if (!strcmp("/inr:ghost", In.top())) {
		ParamMode='G';
	} else if (!strcmp("/inr:manual", In.top())) {
		ParamMode='M';
	} else if (!strcmp("/inr", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByInr();
		ClearParamsAndArgs();
	} else if (!strcmp("/blk:full", In.top())) {
		ParamFull=true;
	} else if (!strcmp("/blk:clear", In.top())) {
		ParamClear=true;
	} else if (!strcmp("/blk", In.top())) {
		if (ParamClear) {
			NoArgsAllowed("/blk:clear");
		}
		ModifyBlacklist();
		ClearParamsAndArgs();
	} else if (!strcmp("/pth:full", In.top())) {
		ParamFull=true;
	} else if (!strcmp("/pth", In.top())) {
		Done=KillByPth();
		ClearParamsAndArgs();
	} else if (!strcmp("/ogl:simple", In.top())) {
		ParamSimple=true;
	} else if (!strcmp("/ogl:soft", In.top())) {
		ParamSoft=true;
	} else if (!strcmp("/ogl", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByOgl();
		ClearParamsAndArgs();
	} else if (!strcmp("/d3d:simple", In.top())) {
		ParamSimple=true;
	} else if (!strcmp("/d3d:soft", In.top())) {
		ParamSoft=true;
	} else if (!strcmp("/d3d", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByD3d();
		ClearParamsAndArgs();
	} else if (!strcmp("/d2d:simple", In.top())) {
		ParamSimple=true;
	} else if (!strcmp("/d2d:strict", In.top())) {
		ParamStrict=true;
	} else if (!strcmp("/d2d", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByD2d();
		ClearParamsAndArgs();
	} else if (!strcmp("/gld:simple", In.top())) {
		ParamSimple=true;
	} else if (!strcmp("/gld:strict", In.top())) {
		ParamStrict=true;
	} else if (!strcmp("/gld", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByGld();
		ClearParamsAndArgs();
	} else if (!strcmp("/fsc:strict", In.top())) {
		ParamStrict=true;
	} else if (!strcmp("/fsc:apps", In.top())) {
		ParamApps=true;
	} else if (!strcmp("/fsc", In.top())) {
		NoArgsAllowed(In.top());
		Done=KillByFsc();
		ClearParamsAndArgs();
	} else if (!strcmp("/bpp", In.top())) {
		NoArgsAllowed(In.top());
		MessageBeep(MB_ICONINFORMATION);
		ClearParamsAndArgs();
	} else if (!strcmp("/hlp", In.top())) {
		NoArgsAllowed(In.top());
		PrintUsage();
		Done=true;
		ModeIgnore=false;
#ifdef HIDDEN
		ModeVerbose=true;
#else
		ModeVerbose=false;
#endif
		ClearParamsAndArgs();
	} else if (!strcmp("/ver", In.top())) {
		NoArgsAllowed(In.top());
		PrintVersion();
		Done=true;
		ModeIgnore=false;
#ifdef HIDDEN
		ModeVerbose=true;
#else
		ModeVerbose=false;
#endif
		ClearParamsAndArgs();
	} else if (!strcmp("+v", In.top())) {
		ModeVerbose=true;
	} else if (!strcmp("-v", In.top())) {
		ModeVerbose=false;
	} else if (!strcmp("/sec", In.top())) {
		NoArgsAllowed(In.top());
		while ((Done=SecuredExecution(RP.mutex))&&RP.loop) 
			Sleep(1000);
		ClearParamsAndArgs();
	} else if (In.top()[0]=='=') {
		ArgWcard=In.top()+1;
	} else {
		if (In.top()[0]=='+'||In.top()[0]=='-') {
			cerr<<"Warning: unknown setting "<<In.top()<<"!"<<endl;
		} else {
			if (strchr(In.top(), ':')) {
				cerr<<"Warning: unknown parameter "<<In.top()<<"!"<<endl;
			} else {
				cerr<<"Warning: unknown switch "<<In.top()<<"!"<<endl;
				if (ArgWcard) {
					cerr<<"Warning: no arguments allowed for unknown switch ("<<RP.arg<<")!"<<endl;
					ArgWcard=NULL;
				}
			}
		}
	}

	In.pop();
	return !In.empty()&&(!Done||ModeIgnore);
}

Controller::MakeItDead(stack<char*> &In)
{
	while (MakeItDeadInternal(In));
	
	if (ModeVerbose) WaitForUserInput();
	
	if (sec_mutex) CloseHandle(sec_mutex);
}