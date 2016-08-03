#ifndef EXTRA_H
#define EXTRA_H

#include "ConOut.h"
#include <functional>
#include <memory>
#include <windows.h>
#include <winternl.h>

#define PTR_32(Type) ULONG
#define PTR_64(Type) ULONGLONG

class Extras {
private:
	static std::unique_ptr<Extras> instance;
	
	Win32WcostreamBuf wcout_win32;
	Win32WcostreamBuf wcerr_win32;
	HMODULE hUser32;
	HMODULE hNtDll;
	HMODULE hKernel32;
	HMODULE hShlwapi;
	
	void LoadFunctions();
	void UnloadFunctions();
	
	Extras(bool hidden, const wchar_t* caption);
public:
	~Extras();
	Extras(const Extras&)=delete;				//Get rid of default copy constructor
	Extras& operator=(const Extras&)=delete;	//Get rid of default copy assignment operator
	void WcoutMessageBox();						//Not making this static for the uniformity of calling extra functions (through extern "fn" pointers)
	void EnableWcout(bool value);				//Not making this static for the uniformity of calling extra functions (through extern "fn" pointers)
	
	static bool MakeInstance(bool hidden, const wchar_t* caption);	
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
typedef BOOL (WINAPI *pIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
typedef BOOL (WINAPI *pPathFindOnPathW)(LPWSTR lpszFile, LPCWSTR* lppszOtherDirs);
typedef BOOL (WINAPI *pWow64DisableWow64FsRedirection)(PVOID *OldValue);
typedef BOOL (WINAPI *pWow64RevertWow64FsRedirection)(PVOID OldValue);
typedef BOOL (WINAPI *pAttachConsole)(DWORD dwProcessId);
typedef std::function<void(void)> pWcoutMessageBox;
typedef std::function<void(bool)> pEnableWcout;

#endif //EXTRA_H
