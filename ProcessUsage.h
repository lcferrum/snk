#ifndef PROCESS_H
#define PROCESS_H

#include <vector>
#include <windows.h>

class Processes {
private:
	struct PData {
		double perf;
		DWORD pid;
		bool blacklisted;
		bool system;
		bool disabled;
		bool operator<(const PData &right) const {
			return perf<right.perf;
		}
	};

	std::vector<PData> CAN;
	std::vector<PData>::reverse_iterator current_rit;
	bool all;

	void EnumProcessUsage();
	void FillStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	void ComputeStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	bool FirstValid();
public:
	Processes();
	void SetAll(bool flag);
	bool FirstPID();
	bool NextPID();
	DWORD GetCurrentPID();
	void DisableCurrentPID();
	bool AddBlacklist(bool Full, char* Wcard);
	bool EraseBlacklist();
};

#endif //PROCESS_H
