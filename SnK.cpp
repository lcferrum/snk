#include <stdio.h>
#include <stack>
#include <iostream>
#include <limits>
#include "ProcessUsage.h"
//#include "Killers.h"
#include "Extra.h"
#include "Help.h"

#ifdef HIDDEN
#include "ConRedirection.h"
#endif

int main(int argc, char* argv[])
{
	std::stack<char*> Rules;
	char *head, *token, *rule;
	size_t buff_len;
	char stngs_cmd;
	bool insert_arg;
	
#ifdef HIDDEN
	CaptureCout();
#endif
	
	/*if (argc<2) {
		PrintVersion();
#ifdef HIDDEN
		std::cout<<"Press OK to continue... "<<std::endl;
		MessageBox(NULL, GetCoutBuf().c_str(), "Search and Kill", MB_ICONWARNING|MB_SETFOREGROUND);
		ReleaseCout();
		std::cout<<GetCoutBuf();
#endif
		return 0;
	}*/
	
	Load_Extra();
	
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
		
		std::cerr<<"Warning: unknown input: "<<argv[argc]<<std::endl;
	}

#ifdef DEBUG
	{
		std::stack<char*> _Rules=Rules;
		std::cout<<"Rules (unfolding stack):"<<std::endl;
		while (!_Rules.empty()) {
			std::cout<<"\t\t"<<_Rules.top()<<std::endl;
			_Rules.pop();
		}
	}
#endif

	Processes processes;
	
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	
	UnLoad_Extra();	
#ifdef HIDDEN
	ReleaseCout();
	
	std::cout<<GetCoutBuf();
#endif	
	
	return 0;
}