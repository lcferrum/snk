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
	bool discarded;				//Indicates that process is now untouchable and will be omitted from any queries
	bool disabled;				//Indicates that process has already been killed (or at least was tried to be killed) and should be omitted from any further queries
	bool system;				//Indicates that this is a system process (i.e. process that wasn't created by user)
	std::wstring name;			//Name of the process executable
	std::wstring path;			//Full path to the process executable
	PData *ref;					//Reference instead of current object could be used for some methods
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
	bool GetDiscarded() const { return discarded; }
	void SetDiscarded(bool value) { discarded=value; }
	bool GetDisabled() const { return ref?ref->GetDisabled():disabled; }
	void SetDisabled(bool value) { if (ref) ref->SetDisabled(value); else disabled=value; }
	void SetReference(PData* value) { ref=value; }
	std::wstring GetName() const { return name; }
	std::wstring GetPath() const { return path; }

	bool ComputeDelta(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur);
	PData(ULONGLONG prck_time_cur, ULONGLONG prcu_time_cur, ULONGLONG crt_time_cur, ULONG_PTR pid, bool odd_enum, UNICODE_STRING name, const std::wstring &path, bool system);
};

//This is common parent for cross delegation of ApplyToProcesses function with Killers policy
class ProcessesCrossBase {
protected:
	virtual bool ApplyToProcesses(std::function<bool(ULONG_PTR, const std::wstring&, const std::wstring&, bool)> mutator)=0;
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
	virtual bool ModeBlank()=0;
	virtual bool ModeBlacklist()=0;
	virtual bool ModeWhitelist()=0;
protected:
	enum LstMode:char {LST_SHOW=0, LST_DEBUG, INV_MASK, CLR_MASK};	//Default mode should be 0 so variable can be reset by assigning it 0 or false

	//Applies function ("mutator") to processes from CAN according to currently active modes
	//If "mutator" returned TRUE - marks this PID as disabled and exits loop 
	bool ApplyToProcesses(std::function<bool(ULONG_PTR, const std::wstring&, const std::wstring&, bool)> mutator);
	
	//TODO
	void Synchronize(Processes &ref);

	//TODO
	void ManageProcessList(LstMode param_lst_mode);	
	
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
