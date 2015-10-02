#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stack>
#include <windows.h>
#include "Killers.h"

class Controller: public Killers {
private:
	bool ModeIgnore;
	bool ModeVerbose;
	HANDLE ModeMutex;
	
	NoArgsAllowed(char* sw);
	WaitForUserInput();
	SecuredExecution();
	MakeItDeadInternal(stack<char*> &In);
public:
	MakeItDead(stack<char*> &In);
	Controller();
};
															
#endif //CONTROLLER_H