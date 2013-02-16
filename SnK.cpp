#include <stdio.h>
#include <stack>
#include <map>
#include <iostream>
#include <limits>
#include <windows.h>
#include <conio.h>
#include "ProcessUsage.h"
#include "Killers.h"
#include "Extra.h"
#include "Help.h"

#ifdef HIDDEN
#include "ConRedirection.h"
#endif

#define MUTEX_NAME			"Global\\MUTEX_SNK_8b52740e359a5c38a718f7e3e44307f0"

struct RULES_PROP {
	bool	fsc_strict;
	bool	apps;
	bool 	aim;
	bool	ogl_soft;
	bool	ogl_simple;
	bool	d3d_soft;
	bool	d3d_simple;
	bool	d2d_simple;
	bool	d2d_strict;
	bool	gld_strict;
	bool	gld_simple;
	bool	anykey;
	bool	verbose;
	bool	full;
	bool	lcase;
	char	inr_mode;
	char*	arg;
	HANDLE 	mutex;
};

using namespace std;

bool MakeItDead(stack<char*> &In, multimap<float, DWORD> &CAN, RULES_PROP &RP);

void WaitForUserInput(bool anykey);

bool SecuredExecution(HANDLE &mutex);

void NoArgsAllowed(char* arg, char* sw);

int main(int argc, char* argv[])
{
	stack<char*> Rules;
	multimap<float, DWORD> Processes;
	char *head, *token, *rule;
	int buff_len;
	char stngs_cmd;
	bool insert_arg;
	RULES_PROP RulesProp;
	
	RulesProp.aim=false;
	RulesProp.fsc_strict=false;
	RulesProp.apps=false;
	RulesProp.ogl_soft=false;
	RulesProp.ogl_simple=false;
	RulesProp.d3d_soft=false;
	RulesProp.d3d_simple=false;
	RulesProp.d2d_simple=false;
	RulesProp.d2d_strict=false;
	RulesProp.gld_simple=false;
	RulesProp.anykey=false;
	RulesProp.verbose=false;
	RulesProp.full=false;
	RulesProp.lcase=false;
	RulesProp.gld_strict=false;
	RulesProp.inr_mode='H';
	RulesProp.arg=NULL;
	RulesProp.mutex=NULL;
	
#ifdef HIDDEN
	CaptureCout();
#endif
	
	if (argc<2) {
		PrintVersion();
#ifdef HIDDEN
		cout<<"Press OK to continue... "<<endl;
		MessageBox(NULL, GetCoutBuf().c_str(), "Search and Kill", MB_ICONWARNING|MB_SETFOREGROUND);
		ReleaseCout();
		cout<<GetCoutBuf();
#endif
		return 0;
	}
	
	Load_Extra();
	
	/****TEST***
	while (argc>1) {
		cout<<"\t\t"<<argv[--argc]<<endl;
	}
	****TEST***/
	
	while (argc>1) {
		argc--;
		
		if (argv[argc][0]=='/') {
			if (head=strchr(argv[argc], '=')) {
				token=new char[strlen(head)+1];
				strcpy(token, head);
				*head=0;
				insert_arg=true;
			} else insert_arg=false;
		
			buff_len=strlen(argv[argc])+1;
			
			head=strtok(argv[argc], ":");
			rule=new char[buff_len];
			strcpy(rule, head);
			Rules.push(rule);
			
			if (insert_arg) Rules.push(token);
			
			while (token=strtok(NULL, ":")) {
				rule=new char[buff_len];
				strcpy(rule, head);
				strcat(rule, ":");
				strcat(rule, token);
				Rules.push(rule);
			}
			
			continue;
		}
		
		if (argv[argc][0]=='+'||argv[argc][0]=='-') {
			stngs_cmd=argv[argc][0];
		
			while (*++argv[argc]!='\0') {
				rule=new char[3];
				rule[0]=stngs_cmd;
				rule[1]=*argv[argc];
				rule[2]='\0';
				Rules.push(rule);
			}
			
			continue;
		}
		
		cerr<<"Warning: unknown input: "<<argv[argc]<<endl;
	}

	/****TEST***
	while (!Rules.empty()) {
		cout<<"\t\t"<<Rules.top()<<endl;
		Rules.pop();
	}
	****TEST***/

	EnumProcessUsage(Processes, false);
	
	/****TEST***
	multimap<float, DWORD>::iterator it;
	for (it=Processes.begin(); it!= Processes.end(); it++)
		cout<<(*it).second<<" => "<<(*it).first<<"%"<<endl;
	****TEST***/
	
	while (MakeItDead(Rules, Processes, RulesProp));
	
	if (RulesProp.verbose) WaitForUserInput(RulesProp.anykey);
	
	if (RulesProp.mutex) CloseHandle(RulesProp.mutex);

	UnLoad_Extra();	
#ifdef HIDDEN
	ReleaseCout();
	
	cout<<GetCoutBuf();
#endif	
	
	return 0;
}

bool MakeItDead(stack<char*> &In, multimap<float, DWORD> &CAN, RULES_PROP &RP) {
	bool Done=false;

    if (In.empty()) return false;
	
	if (!strcmp("+t", In.top())) {
		RP.aim=true;
	} else if (!strcmp("-t", In.top())) {
		RP.aim=false;
	} else if (!strcmp("/cpu", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByCpu(CAN, RP.aim);
		RP.arg=NULL;
	} else if (!strcmp("+a", In.top())) {
		EnumProcessUsage(CAN, true);
	} else if (!strcmp("-a", In.top())) {
		EnumProcessUsage(CAN, false);
	} else if (!strcmp("/inr:ghost", In.top())) {
		if (RP.inr_mode=='H') RP.inr_mode='G';
	} else if (!strcmp("/inr:manual", In.top())) {
		if (RP.inr_mode=='H') RP.inr_mode='M';
	} else if (!strcmp("/inr", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByInr(CAN, RP.inr_mode, RP.aim);
		RP.inr_mode='H';
		RP.arg=NULL;
	} else if (!strcmp("/pth:full", In.top())) {
		RP.full=true;
	} else if (!strcmp("/pth:lcase", In.top())) {
		RP.lcase=true;
	} else if (!strcmp("/pth", In.top())) {
		Done=KillByPth(CAN, RP.full, RP.lcase, RP.aim, RP.arg);
		RP.lcase=false;
		RP.full=false;
		RP.arg=NULL;
	} else if (!strcmp("/ogl:simple", In.top())) {
		RP.ogl_simple=true;
	} else if (!strcmp("/ogl:soft", In.top())) {
		RP.ogl_soft=true;
	} else if (!strcmp("/ogl", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByOgl(CAN, RP.ogl_simple, RP.ogl_soft, RP.aim);
		RP.ogl_simple=false;
		RP.ogl_soft=false;
		RP.arg=NULL;
	} else if (!strcmp("/d3d:simple", In.top())) {
		RP.d3d_simple=true;
	} else if (!strcmp("/d3d:soft", In.top())) {
		RP.d3d_soft=true;
	} else if (!strcmp("/d3d", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByD3d(CAN, RP.d3d_simple, RP.d3d_soft, RP.aim);
		RP.d3d_soft=false;
		RP.d3d_simple=false;
		RP.arg=NULL;
	} else if (!strcmp("/d2d:simple", In.top())) {
		RP.d2d_simple=true;
	} else if (!strcmp("/d2d:strict", In.top())) {
		RP.d2d_strict=true;
	} else if (!strcmp("/d2d", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByD2d(CAN, RP.d2d_simple, RP.d2d_strict, RP.aim);
		RP.d2d_simple=false;
		RP.d2d_strict=false;
		RP.arg=NULL;
	} else if (!strcmp("/gld:simple", In.top())) {
		RP.gld_simple=true;
	} else if (!strcmp("/gld:strict", In.top())) {
		RP.gld_strict=true;
	} else if (!strcmp("/gld", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByGld(CAN, RP.gld_simple, RP.gld_strict, RP.aim);
		RP.gld_strict=false;
		RP.gld_simple=false;
		RP.arg=NULL;
	} else if (!strcmp("/fsc:strict", In.top())) {
		RP.fsc_strict=true;
	} else if (!strcmp("/fsc:apps", In.top())) {
		RP.apps=true;
	} else if (!strcmp("/fsc", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=KillByFsc(CAN, RP.fsc_strict, RP.apps, RP.aim);
		RP.fsc_strict=false;
		RP.apps=false;
		RP.arg=NULL;
	} else if (!strcmp("/bpp", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		MessageBeep(MB_ICONINFORMATION);
		RP.arg=NULL;
	} else if (!strcmp("/hlp", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		PrintUsage();
		Done=true;
		RP.arg=NULL;
	} else if (!strcmp("/ver", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		PrintVersion();
		Done=true;
		RP.arg=NULL;
#ifndef HIDDEN
	} else if (!strcmp("+k", In.top())) {
		RP.anykey=true;
	} else if (!strcmp("-k", In.top())) {
		RP.anykey=false;
#endif
	} else if (!strcmp("+v", In.top())) {
		RP.verbose=true;
	} else if (!strcmp("-v", In.top())) {
		RP.verbose=false;
	} else if (!strcmp("/sec", In.top())) {
		NoArgsAllowed(RP.arg, In.top());
		Done=SecuredExecution(RP.mutex);
		RP.arg=NULL;
	} else if (In.top()[0]=='=') {
		RP.arg=In.top()+1;
	} else {
		if (In.top()[0]=='+'||In.top()[0]=='-') {
			cerr<<"Warning: unknown setting "<<In.top()<<"!"<<endl;
		} else {
			if (strchr(In.top(), ':')) {
				cerr<<"Warning: unknown parameter "<<In.top()<<"!"<<endl;
			} else {
				cerr<<"Warning: unknown switch "<<In.top()<<"!"<<endl;
				if (RP.arg) {
					cerr<<"Warning: no arguments allowed for unknown switch ("<<RP.arg<<")!"<<endl;
					RP.arg=NULL;
				}
			}
		}
	}

	In.pop();
	return !In.empty()&&!Done;
}

void WaitForUserInput(bool anykey) {
#ifndef HIDDEN
	if (anykey) {
		int c;
		cout<<"Press ANY KEY to continue... "<<endl;
		c=getch();
		if (c==0||c==224) getch();
	} else {
		cout<<"Press ENTER to continue... "<<flush;
		cin.ignore(numeric_limits<streamsize>::max(), '\n');	//Needs defined NOMINMAX
	}
#else
	cout<<"Press OK to continue... "<<endl;
	MessageBox(NULL, GetCoutBuf().c_str(), "Search and Kill", MB_ICONWARNING|MB_SETFOREGROUND);
#endif
}

bool SecuredExecution(HANDLE &mutex) {
	SECURITY_ATTRIBUTES mutex_sa;
	PSECURITY_DESCRIPTOR p_mutex_sd;
	
	if (mutex) {
		cout<<"Secured execution: this instance is already secured!"<<endl;
		return false;
	}
	
	if (!(p_mutex_sd=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) return false; 
	if (!InitializeSecurityDescriptor(p_mutex_sd, SECURITY_DESCRIPTOR_REVISION)) return false;
	if (!SetSecurityDescriptorDacl(p_mutex_sd, true, (PACL)NULL, true)) return false;
	mutex_sa.nLength=sizeof(SECURITY_ATTRIBUTES); 
	mutex_sa.lpSecurityDescriptor=p_mutex_sd;
	mutex_sa.bInheritHandle=false; 
	mutex = CreateMutex(&mutex_sa, false, MUTEX_NAME);
	LocalFree(p_mutex_sd);
	
	if (mutex) {
		if (GetLastError()==ERROR_ALREADY_EXISTS) {
			cout<<"Secured execution: another secured SnK instance is already running!"<<endl;
			CloseHandle(mutex);
			mutex=NULL;
			return true;
		} else {
			cout<<"Secured execution: SnK instance secured!"<<endl;
			return false;
		}
	}
	
	return false;
}

void NoArgsAllowed(char* arg, char* sw) {
	if (arg) {
		cerr<<"Warning: switch "<<sw<<" doesn't allow arguments ("<<arg<<")!"<<endl;
	}
}
