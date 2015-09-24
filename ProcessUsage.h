#ifndef PROCESS_H
#define PROCESS_H

#include <vector>
#include <functional>
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

	std::vector<PData> CAN;	//Stupid name stucked from the previous version
							//Actually it's a reference to Fallout Van Buren design docs
							//In Van Buren "dataCAN" represents a high-capacity storage medium for mainframes
	std::vector<PData>::reverse_iterator current_rit;
	bool all;
	bool loop;

	void EnumProcessUsage();
	void FillStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	void ComputeStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	bool FirstValid();
public:
	Processes();
	void SetAll(bool flag);
	void SetLoop(bool flag);
	bool ApplyToProcesses(std::function<bool(DWORD)> mutator);
	bool FirstPID();
	bool NextPID();
	DWORD GetCurrentPID();
	void DisableCurrentPID();
	bool AddBlacklist(bool Full, char* Wcard);
	bool EraseBlacklist();
};

#endif //PROCESS_H
