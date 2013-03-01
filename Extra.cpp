#include "Extra.h"
#include <iostream>

typedef HWND (WINAPI *pNtUserHungWindowFromGhostWindow)(HWND hwndGhost);
pNtUserHungWindowFromGhostWindow fnNtUserHungWindowFromGhostWindow;

HINSTANCE g_hUser32;

bool Load_Extra() {
	g_hUser32=NULL;
	g_hUser32=LoadLibrary("user32.dll");

	if (!g_hUser32) return false;

	fnNtUserHungWindowFromGhostWindow=(pNtUserHungWindowFromGhostWindow)GetProcAddress(g_hUser32, "HungWindowFromGhostWindow");

	if (!fnNtUserHungWindowFromGhostWindow) return false;

	return true;
}

void UnLoad_Extra() {
	if (g_hUser32) FreeLibrary(g_hUser32);
}

HWND extraUserHungWindowFromGhostWindow(HWND hwndGhost) {
	if (fnNtUserHungWindowFromGhostWindow) {
		return fnNtUserHungWindowFromGhostWindow(hwndGhost);
	} else return NULL;
}

void checkUserHungWindowFromGhostWindow() {
	if (!fnNtUserHungWindowFromGhostWindow)
		std::cerr<<"HungWindowFromGhostWindow not found in user32.dll!"<<std::endl;
}
