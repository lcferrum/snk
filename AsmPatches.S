.file "AsmPatches.S"
.text								/* Code section */
.globl _EnumDisplayDevicesWrapper	/* Make function visible to linker, underscore shows that it is CDECL */
.def _EnumDisplayDevicesWrapper		/* Defining symbol, COFF format */
	.scl 2							/* Storage-class: 2 = external */
	.type 32						/* Attribute: 32 = function */
.endef
	
_EnumDisplayDevicesWrapper:
#ifndef _WIN64
	/* 
	Function prototype is BOOL __cdecl EnumDisplayDevicesWrapper(LPCTSTR, DWORD, PDISPLAY_DEVICE, DWORD, fnPtr, DWORD)
	6 DWORDs are passed on the stack: 
	 First is a return address
	 Next 4 DWORDs are actual function parameters which will be passed to EnumDisplayDevices function
	 Last 2 DWORDs are also function parameters:
	  First one is EnumDisplayDevices function pointer and also will be used to store return address
	  Second one will be used to store EBP
	We are not using stack frame so current stack can be used to call EnumDisplayDevices
	All the hacking is to be able to call EnumDisplayDevices with variable number of parameters
	Not using __imp__EnumDisplayDevicesW@16 symbol directly because Clang's AS doesn't uderstand STDCALL mangling
	*/
	movl 20(%esp), %eax							/* Moving EnumDisplayDevices pointer to EAX */
	movl %ebp, 24(%esp)							/* Saving EBP to the last DWORD on the stack */
	movl %esp, %ebp								/* Saving stack pointer to EBP */
	popl 20(%ebp)								/* Removing return address from the stack and saving it to the second-to-last DWORD on the stack */
	call *%eax									/* Calling EnumDisplayDevices: it's STDCALL but function may take less params than expected and won't clear the stack properly */
	movl %ebp, %esp								/* By STDCALL convention EBP is non-volatile so it still holds original stack pointer after the call - restoring it */
	movl 20(%esp), %ebp							/* Restoring return address */
	movl %ebp, (%esp)							
	movl 24(%esp), %ebp							/* Restoring EBP */
#endif
	ret											/* Stack is now returned to it's original state so caller can clear it (by CDECL convention) and return value is in EAX */
