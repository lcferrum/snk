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

	void EnumProcessUsage();
	void FillStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
	void ComputeStatArrays(int index, bool *sys, DWORD* PID, FILETIME* UT, FILETIME* KT, FILETIME* ST);
protected:
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
public:
	Processes();
};

#endif //PROCESS_H
