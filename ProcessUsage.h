#ifndef PROCESS_H
#define PROCESS_H

#include <vector>
#include <string>
#include <functional>
#include <windows.h>
#include <winternl.h>

class PData {
private:
	ULONGLONG prck_time_prv;	//Process kernel time from the last update
	ULONGLONG prcu_time_prv;	//Process user time from the last update
	ULONGLONG crt_time;			//Process creation time
	ULONGLONG prc_time_dlt;		//Process time delta = current kernel+user time - previous kernel+user time
	bool odd_enum;				//Enum period when this PID was last updated (ODD or EVEN)
	ULONG_PTR pid;				//In NT internal structures it is HANDLE aka PVOID (though public Win API function treat PID as DWORD), so cast it to ULONG_PTR like MS recommends
	bool blacklisted;			//Indicates that process is now untouchable and will be omitted from any queries
	bool disabled;				//Indicates that process has already been killed (or at least was tried to be killed) and should be omitted from any further queries
	bool system;				//Indicates that this is a system process (i.e. process that wasn't created by user)
	std::wstring name;			//Name of the process executable
	std::wstring path;			//Full path to the process executable
public:
	bool operator<(const PData &right) const {
		return prc_time_dlt<right.prc_time_dlt;
	}
	
	bool operator==(const ULONG_PTR &right) const {
		return pid==right;
	}
	
	ULONG_PTR GetPID() const { return pid; }
	ULONGLONG GetDelta() const { return prc_time_dlt; }
	ULONGLONG GetCrtTime() const { return crt_time; }
	bool GetOddEnum() const { return odd_enum; }
	bool GetSystem() const { return system; }
	bool GetDisabled() const { return disabled; }
	void SetDisabled(bool value) { disabled=value; }
	bool GetBlacklisted() const { return blacklisted; }
	void SetBlacklisted(bool value) { blacklisted=value; }
	std::wstring GetName() const { return name; }
	std::wstring GetPath() const { return path; }

	bool ComputeDelta(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur);
	PData(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur, ULONG_PTR pid, bool odd_enum, UNICODE_STRING name, const std::wstring &path, bool system);
};

//This is common parent for cross delegation of ApplyToProcesses function with Killers policy
class ProcessesCrossBase {
protected:
	virtual bool ApplyToProcesses(std::function<bool(ULONG_PTR, const std::wstring&, const std::wstring&)> mutator)=0;
};

//This is default Processes policy, that is intended to be used on NT based OSes
class Processes: virtual protected ProcessesCrossBase {
private:
	std::vector<PData> CAN;	//Stupid name stuck from the previous version
							//Actually it's a reference to Fallout Van Buren design docs
							//In Van Buren "dataCAN" represents a high-capacity storage medium for mainframes
	bool odd_enum;			//Current enum period (ODD or EVEN)
	DWORD self_pid;
	PSID self_lsid;
	PVOID wow64_fs_redir;	//OldValue for Wow64DisableWow64FsRedirection/Wow64RevertWow64FsRedirection

	DWORD EnumProcessTimes(bool first_time);
	void EnumProcessUsage();
	void EnableDebugPrivileges();
	PSID GetLogonSID(HANDLE hProcess);	//Always free resulting PSID with FreeLogonSID
	void FreeLogonSID(PSID lsid);
	
	virtual bool ModeAll()=0;
	virtual bool ModeLoop()=0;
protected:
	//Applies function ("mutator") to processes from CAN that are not marked as system
	//If "mutator" returned TRUE - marks this PID as disabled and exits loop 
	//If mode_all - applies "mutator" to the whole CAN, including processes that are marked as system
	//If mode_loop - ignores return result and loops till the end of CAN (disabled processes are still marked)
	bool ApplyToProcesses(std::function<bool(ULONG_PTR, const std::wstring&, const std::wstring&)> mutator);

	//Adds processes that are forbidden to kill to blacklist using path
	//If param_full - uses full process path instead just name
	void AddPathToBlacklist(bool param_full, const wchar_t* arg_wcard);	
	
	//Adds processes that are forbidden to kill to blacklist using PID
	void AddPidToBlacklist(const wchar_t* arg_parray);

	//Clears blacklist of untouchable processes
	void ClearBlacklist();
	
	//Sorts processes list by CPU usage
	void SortByCpuUsage();
	
	//Sorts processes list by creation time
	void SortByRecentlyCreated();
	
	//Prints content of CAN 
	//Mainly for DEBUG
	void DumpProcesses();
public:	
	Processes();
	~Processes();
};

#endif //PROCESS_H
