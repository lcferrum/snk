#ifndef PROCESS_H
#define PROCESS_H

#include <vector>
#include <functional>
#include <windows.h>

class PData {
private:
	unsigned long long int u_time64;
	unsigned long long int k_time64;
	unsigned long long int s_time64;
	unsigned long long int ConvertToUInt64(FILETIME ftime);
public:
	double perf;
	DWORD pid;
	bool blacklisted;
	bool system;
	bool disabled;

	bool operator<(const PData &right) const {
		return perf<right.perf;
	}

	bool ComputePerformance();
	PData(DWORD pid);
};

class Processes {
private:
	std::vector<PData> CAN;	//Stupid name stucked from the previous version
							//Actually it's a reference to Fallout Van Buren design docs
							//In Van Buren "dataCAN" represents a high-capacity storage medium for mainframes

	void AddPData(DWORD PID);
	void ComputePData(PData &data);
	void EnumProcessUsage();
	void EnableDebugPrivileges();
public:
	bool ApplyToProcesses(std::function<bool(DWORD)> mutator);

	bool ModeAll;	//If true - tries to kill even processes that are not accessible by current user
	bool ModeLoop;	//If true - appllies killer function till there are no applicable processes left
	
	bool ParamFull;
	bool ParamClear;
	
	char* ArgWcard;
	
	void ModifyBlacklist();	//Blacklist is the list of processes that are forbidden to kill
							//If not ParamClear - adds process to blacklist using ArgWcard as process name (or full name if ParamFull is set)
							//If ParamClear - clears blacklist
							//[uses ParamFull, ParamClear and ArgWcard]
	
	void ClearParamsAndArgs();	//Clears ParamFull, ParamClear and ArgWcard

	Processes();
};

#endif //PROCESS_H
