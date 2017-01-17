;	Samle AHK script to launch SnK (windowless) with Ctrl+Alt+Backspace
Menu, Tray, Tip, SnK: Ctrl+Alt+BS

;	SnK first try to search for and kill fullscreen app that has highest cpu load
;	If no such app is found it will next try with not responding (hung) app and DirectX app
;	In the end, if everything else fails, it will just kill any process that has highest CPU load
;		/sec switch will prevent accidentially launching several SnKs in quick succession
;		/bpp will make a beep signaling that hotkey was triggered and SnK launched
;		+v enables message box pop up at the end of exection showing results
;	Place SnKh.exe in the same folder as this script for it to find executable
;	Script can be automatically started at Windows startup using Task Scheduler: https://technet.microsoft.com/en-us/library/cc766428.aspx
;	It is recommended to grant scheduled AHK script Admin rights by checking "Run with highest privileges" checkbox
;	This way SnK launched by the script will also have Admin rights
;	For other possible hotkey combinations and options check out official AHK docs: https://autohotkey.com/docs/Hotkeys.htm
$^!BS::Run SnKh.exe /sec /bpp +v /fsc /inr /d3d /cpu

;	Hotkey below is variation of previous hotkey
;	It allows to launch SnK with different commands depending on whether it was long or short hotkey press
;	To enable it - comment previous hotkey, uncomment lines below and assign SnKh calls proper commands
;	If you want to use other modifier keys for hotkey, edit KeyWait commands accordingly
;$^!BS::
;  KeyWait, Ctrl 
;  KeyWait, Alt
;  if (A_TimeSinceThisHotkey > 3000)
;    Run SnKh.exe +v /prn="OnLongPress" /prn
;  else
;    Run SnKh.exe +v /prn="OnShortPress" /prn
;Return