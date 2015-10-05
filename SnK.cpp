#include <stdio.h>
#include <stack>
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
	bool	ignore;
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
	bool	pth_full;
	bool	blk_full;
	bool	blk_clear;
	bool	loop;
	char	inr_mode;
	char*	arg;
	HANDLE 	mutex;
};

using namespace std;

bool MakeItDead(stack<char*> &In, Processes &CAN, RULES_PROP &RP);

void WaitForUserInput(bool anykey);

bool SecuredExecution(HANDLE &mutex);

void NoArgsAllowed(char* arg, char* sw);

int main(int argc, char* argv[])
{
	stack<char*> Rules;
	char *head, *token, *rule;
	size_t buff_len;
	char stngs_cmd;
	bool insert_arg;
	RULES_PROP RulesProp;
	
	RulesProp.aim=false;
	RulesProp.fsc_strict=false;
	RulesProp.apps=false;
	RulesProp.ignore=false;
	RulesProp.ogl_soft=false;
	RulesProp.ogl_simple=false;
	RulesProp.d3d_soft=false;
	RulesProp.d3d_simple=false;
	RulesProp.d2d_simple=false;
	RulesProp.d2d_strict=false;
	RulesProp.gld_simple=false;
	RulesProp.anykey=false;
	RulesProp.verbose=false;
	RulesProp.pth_full=false;
	RulesProp.blk_full=false;
	RulesProp.blk_clear=false;
	RulesProp.gld_strict=false;
	RulesProp.loop=false;
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

	Processes processes;
	
	UnLoad_Extra();	
#ifdef HIDDEN
	ReleaseCout();
	
	cout<<GetCoutBuf();
#endif	
	
	return 0;
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
