#ifndef EXTRA_H
#define EXTRA_H

#include <memory>
#include <functional>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#define PTR_32(Type) ULONG
#define PTR_64(Type) ULONGLONG

class Extras {
private:
	static std::unique_ptr<Extras> instance;
	
	HMODULE hUser32;
	HMODULE hNtDll;
	HMODULE hKernel32;
	HMODULE hShlwapi;
	HMODULE hPsapi;
	
	void LoadFunctions();
	void UnloadFunctions();
	
	Extras();
public:
	~Extras();
	Extras(const Extras&)=delete;				//Get rid of default copy constructor
	Extras& operator=(const Extras&)=delete;	//Get rid of default copy assignment operator
	Extras(const Extras&&)=delete;				//Get rid of default move constructor
	Extras& operator=(const Extras&&)=delete;	//Get rid of default move assignment operator
	
	static bool MakeInstance();	
};

typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef HWND (WINAPI *pNtUserHungWindowFromGhostWindow)(HWND hwndGhost);
typedef NTSTATUS (WINAPI *pNtOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (WINAPI *pNtQuerySymbolicLinkObject)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
typedef NTSTATUS (WINAPI *pNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS (WINAPI *pNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (WINAPI *pNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS (WINAPI *pNtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONGLONG ReturnLength);
typedef NTSTATUS (WINAPI *pNtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PTR_64(PVOID) BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
enum MEMORY_INFORMATION_CLASS {MemoryBasicInformation=0x0, MemorySectionName=0x2};
typedef NTSTATUS (WINAPI *pNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS (WINAPI *pNtWow64QueryVirtualMemory64)(HANDLE ProcessHandle, PTR_64(PVOID) BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONGLONG Size, PULONGLONG ReturnLength);
typedef BOOL (WINAPI *pIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
typedef BOOL (WINAPI *pPathFindOnPathW)(LPWSTR lpszFile, LPCWSTR* lppszOtherDirs);
typedef BOOL (WINAPI *pWow64DisableWow64FsRedirection)(PVOID *OldValue);
typedef BOOL (WINAPI *pWow64RevertWow64FsRedirection)(PVOID OldValue);
typedef HWND (WINAPI *pGetConsoleWindow)(void);
typedef BOOL (WINAPI *pAttachConsole)(DWORD dwProcessId);
typedef BOOL (WINAPI *pGetProcessMemoryInfo)(HANDLE Process, PPROCESS_MEMORY_COUNTERS ppsmemCounters, DWORD cb);

#endif //EXTRA_H
