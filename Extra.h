#ifndef EXTRA_H
#define EXTRA_H

#include <windows.h>

bool Load_Extra();
void UnLoad_Extra();
HWND extraUserHungWindowFromGhostWindow(HWND hwndGhost);
void checkUserHungWindowFromGhostWindow();

bool CheckPath(DWORD PID, bool Full, char* Wcard);
/******** CheckPath syntax ********
* - zero or more characters
? - one character
**********************************/
bool CheckName(DWORD PID, char** Wcards);
/******** CheckName syntax ********
char* Wcards[]={"Wcard1 OR", "Wcard2", NULL};	
* - zero or more characters
? - one character
**********************************/

#endif //EXTRA_H