.file "AsmPatches.S"
.text									/* Code section */
.globl _EnumDisplayDevicesWrapper@24	/* Make function visible to linker, STDCALL name mangling */
/* Defining symbols, COFF format, storage-class 2 (external), attribute 32 (function) */
.def _EnumDisplayDevicesWrapper@24;	.scl 2;	.type 32;	.endef
.def _EnumDisplayDevicesW@16;		.scl 2;	.type 32;	.endef
	
_EnumDisplayDevicesWrapper@24:
#ifndef _WIN64
	/* 
	Function prototype is BOOL __stdcall EnumDisplayDevicesWrapper(LPCTSTR, DWORD, PDISPLAY_DEVICE, DWORD, DWORD, DWORD)
	7 DWORDs are passed on the stack: 
	 First is a return address
	 Next 4 DWORDs are actual function parameters which will be passed to EnumDisplayDevices function
	 Last 2 DWORDs will be used in place of stack frame to store variables
	  First one will be used to store EBP
	  Second one be used to store return address
	We are not using stack frame so to save a few cycles by not moving variables and using present stack to call EnumDisplayDevices
	All the hacking is to be able to call EnumDisplayDevices with variable number of parameters
	*/
	movl %ebp, 20(%esp)							/* Saving EBP to the second-to-last DWORD on the stack */
	movl %esp, %ebp								/* Saving stack pointer to EBP */
	popl 24(%ebp)								/* Removing return address from the stack and saving it to the last DWORD on the stack */
	call _EnumDisplayDevicesW					/* Calling EnumDisplayDevices: it's STDCALL but function may take less params than expected and won't clear the stack properly */
	movl %ebp, %esp								/* Conforming to Intel ABI EBP is non-volatile so it still holds original stack pointer after the call - restoring it */
	addl $20, %esp								/* Cleaning up the stack up to the saved EBP */	
	popl %ebp									/* Restoring EBP */
	ret											/* Stack is now cleared of passed variables (by STDCALL convention) and return value is in EAX */
#else
	ret											/* Conforming Microsoft x64 calling convention, it's caller's responsibility to clean up stack */
#endif
