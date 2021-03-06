Search and Kill

1. License
----------
Copyright (c) 2012-2017 Lcferrum

This program comes with no warranty.
You must use this program at your own risk.
Licensed under BSD license - see LICENSE.TXT file for details.

2. About
--------
Search and Kill (SnK) is a console tool that automatically searches for certain
Windows processes and kills them. Search is accomplished according to SnK input
arguments. This tool is mainly designed to be run with keyboard shortcut. This
could be done with SnK HotkeySuite, that was specifically designed for use with
SnK (https://github.com/lcferrum/snk_hotkeysuite), or by using automation
software like AutoHotkey (http://www.autohotkey.com/). Sample AHK script is
included: check out SnKSampleScript.ahk file.

3. Where to get
---------------
You can compile SnK by yourself (refer to COMPILE.TXT that comes with the
sources) or download binary distribution from Sourceforge:

	https://sourceforge.net/projects/sandk/files/SnK/
    
Main project homepage is at GitHub:

	https://github.com/lcferrum/snk

4. Usage
--------
Usage (SnK with console output): 
       SnK [settings_block|swith[:parametres][=argument]] ...

Usage (windowless SnK with dialog output):
       SnKh [settings_block|swith[:parametres][=argument]] ...

All swithes and settings blocks are executed sequentially, starting from the
first one. Settings block consists of one or more separate settings combined
together and can be either all-set (+) or all-unset (-) block. All settings 
within single settings block and all parametres within single switch are
applied simultaneously. Incorrect swithes, arguments, settings and parametres 
are ignored and warning is issued. Switches starting from hash (#) are silently
ignored (may be used as hashtag-like comments). Switches can return result, and
if result is positive - program will stop execution (you can modify this
behaviour with some settings).

Windowless version prints output only in verbose mode via dialog. But you can
always redirect standart output streams (which are still present) to see it 
either way. The main advantage of windowless version is that it can be run in
the background where it doesn't interfere with other programs, whereas standart
version will open console window (if not already run from console) which will
get focus and become top-level window. E.g. using /fsc switch in non-windowless
SnK could be unreliable because target process will likely lose it's fullscreen
properties due to emerged console window.

Switches:

/hlp
                              Print usage information and exit. Can only be
                              used as first argument, ignored otherwise.
/ver
                              Print version information and exit. Can only be
                              used as first argument, ignored otherwise.
/bpp
                              Make standart Windows 'informational beep' and
                              continue execution.
/prn=TEXT
                              Echo-like switch - will print to stdout whatever
                              passed to it and continue execution.
/sec
                              Secured execution. Will return positive result if
                              there is another instance already running that
                              has executed this switch. Use before other
                              switches with verbose mode to prevent
                              accidentiall subsequent execution of program.
/cpu
                              Kill process with highest cpu load. Will return
                              positive result if process was found. Can return
                              negative result only if there were no user
                              processes running and 'query all processes'
                              mode was turned off.
/d3d[:simple]
                              Kill process that uses Direct3D and has highest
                              cpu load. If 'simple', will use process modules
                              names to find Direct3D process. Otherwise, will
                              use description of modules. Simple method is
                              somewhat less precise but faster. Please check 
                              DetectMatrix.html for more information. Will 
                              return positive result if process was found.
/ogl[:simple]
                              Kill process that uses OpenGL and has highest cpu
                              load. If 'simple', will use process modules names
                              to find OpenGL process. Otherwise, will use
                              description of modules. Simple method is somewhat
                              less precise but faster. Please check 
                              DetectMatrix.html for more information. Will 
                              return positive result if process was found.
/gld[:simple]
                              Kill process that uses Glide and has highest cpu
                              load. If 'simple', will use process modules names
                              to find Glide process. Otherwise, will use
                              description of modules. Simple method is somewhat
                              less precise but faster. Please check 
                              DetectMatrix.html for more information. Will 
                              return positive result if process was found.
/inr[:plus]
                              Kill process that is not responding and has
                              highest cpu load. By default will use standard
                              Windows procedure (IsHungAppWindow) to check if
                              application is hung. That works ok for most of
                              real life cases. If 'plus', will additionally
                              check if window is answering to SendMessage call. 
                              This will help with artificially hung apps (e.g.
                              SuspendThread'ed) Will return positive result if
                              process was found.
/fsc[:anywnd][:primary]
                              Kill process that is running in fullscreen and
                              has highest cpu load. Works with multi-monitor
                              setups. By default only exclusive fullscreen and
                              borderless windowed processes are checked. If 
                              'anywnd', will check processes with any window
                              type, borderless or not. If 'primary', will check
                              only windows that belong to primary display. Will
                              return positive result if process was found.
/fgd[:anywnd]
                              Kill process which window is in foreground. 
                              Though there is always a foreground window, this
                              switch may return nothing if foreground process
                              has 'non-task' window (has no icon on the task
                              bar) or doesn't belong to user and 'query all
                              processes' mode was turned off. If 'anywnd', will
                              also include 'non-task' windows. Will return 
                              positive result if process was found.
/pth[:full]=WCARDS
                              Kill process which name matches one of the 
                              wildcards (delimeted by semicolon) and has
                              highest cpu load. Matching is always 
                              case-insensitive. If 'full', will use full
                              process path instead of just name. Wildcards use
                              standart wildcard characters '?' (exactly one
                              unknown character) and  '*' (zero or more unknown
                              characters). Will return positive result if
                              process was found.
/mod[:full]=WCARDS
                              Kill process that has a module which name matches
                              one of the wildcards (delimeted by semicolon) and
                              has highest cpu load. Matching is always 
                              case-insensitive. If 'full', will use full
                              module path instead of just name. Wildcards use
                              standart wildcard characters '?' (exactly one
                              unknown character) and  '*' (zero or more unknown
                              characters). Will return positive result if
                              process was found.
/pid[:parent|=PIDS]
                              Kill process which PID belongs to PID array and
                              has highest cpu load. PID array consists of PIDs,
                              delimeted by comma or semicolon, and can include
                              descending or ascending ranges. PID must be 
                              decimal (no prefix), hexadecimal ('0x'/'0X' 
                              prefix) or octal ('0' prefix) unsigned integer.
                              If 'parent', instead of using supplied PID array,
                              will use paren process PID. Will return positive
                              result if process was found.
/cmd[:sub][:utf8|:utf16]=FILE
                              Will load additional commands from file and
                              continue execution. Encoding is auto-detected
                              using BOM's. If there is no BOM, it is assumed
                              that encoding is ANSI or you can force correct
                              one using 'utf8' ot 'utf16' params. If 'sub',
                              will execute supplied commands as subroutine.
                              Settings changed inside subroutine won't
                              propagade beyond it (further commands won't be
                              affected) and 'cmd' will return result based on
                              subroutine execution: positive if subroutine
                              reached it's end without triggering on any of the
                              switches and negative otherwise.
/lst[:clrmask|:invmask]
                              List currently available processes - processes
                              that are not already terminated, not blacklisted,
                              within whitelist (if it exists) and non-system
                              (if +a setting wasn't turned on). If 'clrmask',
                              will clear blacklist, reset whitelist and show
                              result. If 'invmask', will swap blacklist with
                              whitelist and show result. In any case - will
                              continue execution afterwards.
/psh=ARGUMENT
                              Push argument to argument stack and continue
                              execution.
/pop[=ENV_VAR]
                              Pop argument from argument stack. Popped argument
                              will be used as argument for the next switch in
                              case that switch won't supply it's own argument
                              (empty or not). If ENV_VAR is supplied - argument
                              will be popped to environment variable ENV_VAR.
                              In either case execution will continue.
/end
                              Unconditionally (i.e. ignoring 'ignore' and
                              'negate' modes) return positive result.

Settings:

+t|-t
                              Will turn 'test' mode on/off. While in test mode,
                              switches only display information about found
                              processes but don't kill them.
+v|-v
                              Will turn 'verbose' mode on/off. While in verbose
                              mode, program will prompt user to press 'enter'
                              before exit.
+a|-a
                              Will turn 'query all processes' mode on/off.
                              While in this mode, process with highest cpu load
                              will be searched among all processes and not just
                              user processes.
+l|-l
                              Will turn 'loop' mode on/off. While in this mode, 
                              every switch will be looped until it finally 
                              returns negative result. Overall result will be
                              posistive if one of the iterations returned
                              positive result.
+i|-i
                              Will turn 'ignore' mode on/off. While in this 
                              mode, even if switch returns positive result SnK
                              execution continues.
+n|-n
                              Will turn 'negate' mode on/off. While in this 
                              mode, results returned by switches are treated as
                              opposite ones. If switch is not designed to
                              return result - nothing happens.        
+b|-b
                              Will turn 'blacklist' mode on/off. While in this 
                              mode, all processes on which switches trigger are
                              added to blacklist. Blacklisted processes will be
                              ignored by all switches. This mode automatically
                              turns on 'query all processes', 'loop', 'ignore'
                              and 'test' modes on while it is active.
+w|-w
                              Will turn 'whitelist' mode on/off. While in this 
                              mode, all processes on which switches trigger are
                              added to whitelist. Switches will query only
                              whitelisted processes. This mode automatically
                              turns on 'query all processes', 'loop', 'ignore'
                              and 'test' modes on while it is active.
+r|-r
                              Will turn 'recently created sort' mode on/off. 
                              While in this mode, switches, instead of 
                              triggering on process with highest cpu usage,
                              trigger on last created process.
+m|-m
                              Will turn 'mute' mode on/off. While in this mode,
                              all stream output (both stdout and stderr) is
                              suppressed.
+c|-c
                              Will turn 'close' mode on/off. While in this mode,
                              instead of terminating app there SnK will try to
                              close it in ordinary way. If app won't respond to
                              close action, it will be terminated.
+e|-e
                              Will turn 'expand environment variables' mode
                              on/off. While in this mode, all the environmet
                              variables passed inside arguments will be
                              expanded before being passed to switch.

5. Usage example
----------------
Example:
       SnK /sec +vt /bpp /d3d /ogl:simple -t /pth="*Skype*"
       
SnK will do the following in this example:

1) Secure current SnK instance. If there is another secured SnK instance
   running already, program will exit without prompting. Otherwise it will
   continue execution.
2) Will turn verbose and test mode on.
3) Will make 'informational beep' and continue.
4) Will search for Direct3D processes. Will continue if nothing was found.
   Will prompt user to press 'enter' if process was found and then exit.
5) Will search for OpenGL processes using 'simple' method. Will continue if
   nothing was found. Will prompt user to press 'enter' if process was found
   and then exit.
6) Will turn test mode off.
7) Will search for process with name similar to "Skype" using case-insensitive
   compare. Will prompt user to press 'enter' if nothing was found and then
   exit. Will kill process and prompt user to press 'enter' if process was
   found and then exit.
