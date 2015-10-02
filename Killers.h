#ifndef KILLERS_H
#define KILLERS_H

#include <windows.h>
#include "ProcessUsage.h"

template <typename ValueType, typename Container>
class OpenAutoProperty {
	friend Container;
private:
	function<ValueType(ValueType, ValueType&)> set;
	function<ValueType(ValueType&)> get;
	ValueType back_value;
public:
    ValueType operator=(const ValueType &value) { return set(value, back_value); }
    operator ValueType() { return get(back_value); }
	
	friend bool operator==(OpenAutoProperty<ValueType, Container> &left, ValueType &right) { return left.back_value==right; }
    friend bool operator!=(OpenAutoProperty<ValueType, Container> &left, ValueType &right) { return left.back_value!=right; }
	
	OpenAutoProperty(): set([](int value, int &back_value){ return back_value=value; }), get([](int &back_value){ return back_value; }), back_value() {}
	OpenAutoProperty(const ValueType &value): OpenAutoProperty() { back_value=value; }
};

class Killers: public Processes {
private:
	void KillProcess(DWORD PID);
public:
	Killers();
	
	bool ModeBlank;		//Issue "blank cartridges" instead of "live rounds"
	
	bool ParamSimple;
	bool ParamSoft;
	OpenAutoProperty<char, Killers> ParamMode;
	bool ParamStrict;
	bool ParamApps;
	
	//Kills process with highest cpu load
	bool KillByCpu();
	//Kills process that uses OpenGL
	//If ParamSimple - uses process modules names to find OpenGL process
	//If not ParamSimple - uses description of modules
	//If ParamSoft - checks if software rendering is in use
	//[the one with highest cpu load]
	//[uses ParamSimple and ParamSoft]
	bool KillByOgl();
	//Kills process that uses DirectX (Direct3D)
	//If ParamSimple - uses process modules names to find DirectX process
	//If not ParamSimple - uses description of modules
	//If ParamSoft - checks if software rendering is in use
	//[the one with highest cpu load]
	//[uses ParamSimple and ParamSoft]	
	bool KillByD3d();	
	//Kills process with window that doesn't respond (Is Not Responding)
	//Modes are Is(H)ungAppWindow, Send(M)essageTimeout and (G)host
	//If H (aka Hung) - checks applications with IsHungAppWindow()
	//If M (aka Manual) - uses SendMessageTimeout() with WM_NULL and 5 sec timeout to find hanged window
	//If G (aka Ghost) - looks for Ghost windows and searches for it true process
	//(uses undocumented function from Vista and higher versions of user32.dll)
	//[the one with highest cpu load]
	//[uses ParamMode]
	bool KillByInr();
	//Kills process that uses DirectDraw (2D Acceleration)
	//If ParamSimple - uses process modules names to find OpenGL process
	//If ParamStrict - checks if DirectDraw is used exclusively, not with Direct3D, OpenGL or Glide
	//If not ParamSimple - uses description of modules
	//N.B. Windowed 3D processes always use DirectDraw with OpenGL or DirectX
	//[the one with highest cpu load]
	//[uses ParamSimple and ParamStrict]
	bool KillByD2d();
	//Kills process that uses Glide (3Dfx)
	//If ParamSimple - uses process modules names to find Glide process
	//If ParamStrict - checks if Glide is used directly, not through OpenGL
	//If not ParamSimple - uses description of modules
	//[the one with highest cpu load]
	//[uses ParamSimple and ParamStrict]
	bool KillByGld();	
	//Kills process running in fullscreen
	//If ParamStrict - checks if ChangeDisplaySettings(...) was called 
	//with CDS_FULLSCREEN flag (through indirect symptoms)
	//If ParamApps - checks windows only with window styles specific to
	//fullscreen application software (in contrast to system software)
	//[the one with highest cpu load]
	//[uses ParamApps and ParamStrict]
	bool KillByFsc();
	//Kills process using it's path (case-insensitive, with globbing)
	//ArgWcard - wildcard to match
	//If ParamFull - uses full path, otherwise uses just name
	//[the one with highest cpu load]
	//[uses ParamFull and ArgWcard]
	bool KillByPth();
	
	void ClearParamsAndArgs();	//Clears ParamSimple, ParamSoft, ParamMode, ParamStrict and ParamApps
};
															
#endif //KILLERS_H