#include <map>
#include <windows.h>

bool KillByCpu(std::multimap<float, DWORD> &CAN, bool Aim); 
															//Kills process with highest cpu load
bool KillByOgl(std::multimap<float, DWORD> &CAN, bool Simple, bool Soft, bool Aim);	
															//Kills process that uses OpenGL
															//If Simple - uses process modules names to find OpenGL process
															//If not Simple - uses description of modules
															//If Soft - checks if software rendering is in use
															//[the one with highest cpu load]
bool KillByD3d(std::multimap<float, DWORD> &CAN, bool Simple, bool Soft, bool Aim);	
															//Kills process that uses DirectX (Direct3D)
															//If Simple - uses process modules names to find DirectX process
															//If not Simple - uses description of modules
															//If Soft - checks if software rendering is in use
															//[the one with highest cpu load]
bool KillByInr(std::multimap<float, DWORD> &CAN, char Mode, bool Aim);
															//Kills process with window that doesn't respond (Is Not Responding)
															//Modes are Is(H)ungAppWindow, Send(M)essageTimeout and (G)host
															//If H (aka Hung) - checks applications with IsHungAppWindow()
															//If M (aka Manual) - uses SendMessageTimeout() with WM_NULL and 5 sec timeout to find hanged window
															//If G (aka Ghost) - looks for Ghost windows and searches for it true process
															//(uses undocumented function from Vista and higher versions of user32.dll)
															//[the one with highest cpu load]
bool KillByD2d(std::multimap<float, DWORD> &CAN, bool Simple, bool Strict, bool Aim);
															//Kills process that uses DirectDraw (2D Acceleration)
															//If Simple - uses process modules names to find OpenGL process
															//If Strict - checks if DirectDraw is used exclusively, not with Direct3D, OpenGL or Glide
															//If not Simple - uses description of modules
															//N.B. Windowed 3D processes always use DirectDraw with OpenGL or DirectX
															//[the one with highest cpu load]
bool KillByGld(std::multimap<float, DWORD> &CAN, bool Simple, bool Strict, bool Aim);	
															//Kills process that uses Glide (3Dfx)
															//If Simple - uses process modules names to find Glide process
															//If Strict - checks if Glide is used directly, not through OpenGL
															//[the one with highest cpu load]
bool KillByFsc(std::multimap<float, DWORD> &CAN, bool Strict, bool Apps, bool Aim);
															//Kills process running in fullscreen
															//If Strict - checks if ChangeDisplaySettings(...) was called 
															//with CDS_FULLSCREEN flag (through indirect symptoms)
															//If Apps - checks windows only with window styles specific to
															//fullscreen application software (in contrast to system software)
															//[the one with highest cpu load]
bool KillByPth(std::multimap<float, DWORD> &CAN, bool Full, bool Aim, char* Wcard);
															//Kills process using it's path (case-insensitive, with globbing)
															//Wcard - wildcard to match
															//If Full - uses full path, otherwise uses just name
															//[the one with highest cpu load]
