;	Samle AHK script to launch SnK (windowsless) with Ctrl+Alt+Backspace
;	SnK first try to search for and kill fullscreen app that has highest cpu load
;	If no such app is found it will next try with DirectX app and OpenGL app
;	In the end, if everything else fails, it will just kill the app with highest CPU load
;		/sec switch will prevent accidentially launching several SnKs in quick succession
;		/bpp will make a beep signaling that hotkey was triggered and SnK launched
;		+v enables message box pop up at the end of exection showing results
;	Place SnKh.exe in the same folder as this script for it to find executable
;	Script can be automatically started at Windows startup using Scheduler: https://technet.microsoft.com/en-us/library/cc748993.aspx
;	It is recommended to grant scheduled AHK script Admin rights by checking "Run with highest privileges" checkbox
;	This way SnK launched by the script will also have Admin rights
$^!BS::Run SnKh.exe /sec /bpp +v /fsc /d3d /ogl /cpu


;	Hotkey below is variation of previous hotkey
;	It allows to launch SnK with different commands depending on whether it was long or short hotkey press
;	To enable it - comment previous hotkey, uncomment lines below and assign SnKh calls proper commands
;$^!BS::
;  KeyWait, Ctrl 
;  KeyWait, Alt
;  if (A_TimeSinceThisHotkey > 3000)
;    Run SnKh.exe +v /prn="OnLongPress" /prn
;  else
;    Run SnKh.exe +v /prn="OnShortPress" /prn
;Return