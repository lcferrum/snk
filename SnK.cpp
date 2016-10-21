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
			std::wcout<<L"\nWhen finished, press OK"<<std::endl;
			fnWcoutMessageBox();
		}
#endif
		return 0;
	}
	
	std::stack<std::wstring> rules;
	MakeRulesFromArgv(argc, argv, rules);
	
	Controller<Processes, Killers> controller;
	
	controller.MakeItDead(rules);

	return 0;
}