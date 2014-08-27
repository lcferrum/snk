#ifndef PROCESS_H
#define PROCESS_H

#include <map>
#include <windows.h>

class Processes {
private:
	struct PData {
		DWORD pid;
		bool blacklisted;
		bool system;
		bool disabled;
	};

	std::multimap<float, PData> CAN;
	std::multimap<float, PData>::reverse_iterator current_rit;
	bool all;

	void EnumProcessUsage();
	void FillStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	void ComputeStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	bool FirstValid();
public:
	Processes();
	void SetAll(bool flag);
	bool ResetIteration();
	bool NextIteration();
	bool NotEnd();
	DWORD GetCurrentPid();
	void DisableCurrentPid();
	bool AddBlacklist(bool Full, char* Wcard);
	bool EraseBlacklist();
};

#endif //PROCESS_H
