#include <cstdio>
#include <cwchar>
#include <stack>
#include <iostream>
#include <limits>
#include "ProcessUsage.h"
#include "Controller.h"
#include "Killers.h"
#include "Extras.h"
#include "Common.h"
#include "Hout.h"

extern pWcoutMessageBox fnWcoutMessageBox;
extern template class Controller<Processes, Killers>;

#ifdef OBSOLETE_WMAIN
typedef struct {
	int newmode;
} _startupinfo;
#undef _CRT_glob
extern int _CRT_glob;
extern "C" void __wgetmainargs(int*, wchar_t***, wchar_t***, int, _startupinfo*);

int main()
{
	wchar_t **enpv, **argv;
	int argc;
	_startupinfo si;
	__wgetmainargs(&argc, &argv, &enpv, _CRT_glob, &si);
#else
extern "C" int wmain(int argc, wchar_t* argv[])
{
#endif
#ifdef HIDDEN
	Extras::MakeInstance(true, L"Search and Kill");
#else
	Extras::MakeInstance(false, NULL);
#endif

	if (argc<2) {
		PrintVersion();
#ifdef HIDDEN
		if (fnWcoutMessageBox) {
			std::wcout<<L"Press OK to continue... "<<std::endl;
			fnWcoutMessageBox();
		}
#endif
		return 0;
	}
	
	std::stack<std::wstring> rules;
	wchar_t *head, *token;
	while (argc-->1) switch (*argv[argc]) {
		case L'/':
			if ((token=wcschr(argv[argc], L'=')))
				*token++=L'\0';
		
			rules.push((head=wcstok(argv[argc], L":")));
			
			if (token)
				rules.push(std::wstring(L"=")+token);
			
			while ((token=wcstok(NULL, L":")))
				rules.push(head+std::wstring(L":")+token);
			
			continue;
		case L'+':
		case L'-':
			head=argv[argc];
		
			while (*++argv[argc]!=L'\0')
				rules.push({*head, *argv[argc]});
			
			continue;
		default:
			std::wcerr<<L"Warning: unknown input: "<<argv[argc]<<std::endl;
	}
	//After above loop ARGV and ARGC are corrupted beyond repair so don't use them

#if DEBUG>=3
	{
		std::stack<std::wstring> _rules=rules;
		std::wcerr<<L"" __FILE__ ":main:"<<__LINE__<<L": Rules (unfolding stack)..."<<std::endl;
		while (!_rules.empty()) {
			std::wcerr<<L"\t\t"<<_rules.top()<<std::endl;
			_rules.pop();
		}
	}
#endif

	Controller<Processes, Killers> controller;
	
	controller.MakeItDead(rules);
	
	return 0;
}