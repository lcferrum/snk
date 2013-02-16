Search and Kill

1. License
----------
Copyright (c) 2012 Lcferrum

This program comes with no warranty.
You must use this program at your own risk.
Licensed under BSD license – see LICENSE.TXT file for details.

2. About
--------
Search and Kill (SnK) is a console tool that automatically searches for certain
Windows processes and kills them. Search is accomplished according to SnK input
arguments. This tool is mainly designed to be run with keyboard shortcut. This
could be done through creating special Windows shortcut to SnK 
(http://support.microsoft.com/kb/310417) or by using specialised software like
AutoHotkey (http://www.autohotkey.com/).

3. Where to get
---------------
You can compile SnK by yourself (refer to COMPILE.TXT) or download binary
distribution from Sourceforge:

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
are ignored. Switches can return result, and if result is positive program will
stop execution.

Windowless version prints output only in verbose mode via dialog. But you can
always redirect standart output streams (which is still present) to see it 
either way. The main advantage of windowless version is that it can be run in
the background where it doesn't interfere with other programs, whereas standart
version will open console window (if not already run from console) which will
get focus and become top-level window. E.g. using /fsc switch in non-windowless
SnK could be unreliable because target process will likely lose it's fullscreen
properties due to emerged console window.

Switches:

/hlp                          
                              Print usage information and exit.
/ver                          
                              Print version information and exit.
/bpp                          
                              Make standart Windows 'informational beep' and
                              continue execution.
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
/d3d[:simple][:soft]          
                              Kill process that uses Direct3D and has highest
                              cpu load. If 'simple', will use process modules
                              names to find Direct3D process. Otherwise, will
                              use description of modules. Simple method is
                              somewhat less precise but faster. If 'soft', will
                              kill only processes that use software rendering.
                              Please check DetectMatrix.html for more
                              information. Will return positive result if 
                              process was found.
/ogl[:simple][:soft]          
                              Kill process that uses OpenGL and has highest cpu
                              load. If 'simple', will use process modules names
                              to find OpenGL process. Otherwise, will use
                              description of modules. Simple method is somewhat
                              less precise but faster. If 'soft', will kill
                              only processes that use software rendering.
                              Please check DetectMatrix.html for more
                              information. Will return positive result if
                              process was found.
/d2d[:simple][:strict]                 
                              Kill process that uses DirectDraw and has highest
                              cpu load. If 'simple', will use process modules
                              names to find DirectDraw process. Otherwise, will
                              use description of modules. Simple method is
                              somewhat less precise but faster. If 'strict',
                              will kill only processes that use DirectDraw
                              exclusively, and not together with OpenGL, 
                              Direct3D or Glide. Please check DetectMatrix.html
                              for more information. Will return positive result
                              if process was found.
/gld[:simple][:strict]        
                              Kill process that uses Glide and has highest cpu
                              load. If 'simple', will use process modules names
                              to find Glide process. Otherwise, will use
                              description of modules. Simple method is somewhat
                              less precise but faster. If 'strict', will kill
                              only processes that use Glide exclusively, and
                              not through OpenGL intermediate implementation.
                              Please check DetectMatrix.html for more
                              information. Will return positive result if
                              process was found.
/inr[:manual|:ghost]          
                              Kill process that is not responding and has
                              highest cpu load. By default will use standart
                              Windows procedure to check if application is
                              hung. If 'manual', will use custom procedure to
                              check if application is hung - this is somewhat
                              more precise but slower method. If 'ghost', will
                              kill only hung applications with ghosted windows.
                              'Ghost' method is only working on Windows Vista
                              and above - it will always return negative result
                              on lower versions of Windows. "Preciseness" of
                              'manual' method really means that it can detect
                              hung process at earlier stage of "hungness" than
                              Windows standart procedure. So, if process is
                              already hung for a long time - there is no point 
                              in using 'manual' method. Will return positive 
                              result if process was found.
/fsc[:apps][:strict]          
                              Kill process that is running in fullscreen and
                              has highest cpu load. If 'apps', will check only
                              non-system windows to find fullscreen process.
                              Otherwise, will check all windows. If 'strict',
                              before searching for fullscreen processes will
                              check, using current state of OS, if any process
                              has actually requested fullscreen mode. If
                              fullscreen mode wasn't requested - will skip
                              search and assume that process wasn't found. This
                              will speed up search but make it somewhat less
                              precise. Will return positive result if process
                              was found.
/pth[:full][:lcase]=NAME      
                              Kill process whose name matches wildcard 'NAME'
                              and has highest cpu load. If 'full', will use
                              full process path instead of just name. If
                              'lcase', will convert both wildcard and process
                              name to lowercase characters before compare.
                              Wildcard uses standart wildcard characters '?'
                              (exactly one unknown character) and  '*' (zero or
                              more unknown characters). Character '*' doesn't
                              automatically added to any end of 'NAME'. Will 
                              return positive result if process was found.

Settings:
+t|-t                         
                              Will turn test mode on/off. While in test mode,
                              switches only display information about found
                              processes but don't kill them.
+v|-v                         
                              Will turn verbose mode on/off. While in verbose
                              mode, program will prompt user to press 'enter'
                              before exit.
+k|-k                         
                              Will turn 'any key' mode on/off. While this mode
                              and verbose mode is turned on, program will
                              prompt user to press 'any key' before exit.
+a|-a                         
                              Will turn 'query all processes' mode on/off.
                              While in this mode, process with highest cpu load
                              will be searched among all processes and not just
                              user processes.

5. Usage example
----------------                              
Example:
       SnK /sec +vkt /bpp /d3d /ogl:soft:simple -tk /pth:lcase="*Skype*"
       
SnK will do the following in this example:

1) Secure current SnK instance. If there is another secured SnK instance
   running already, program will exit without prompting. Otherwise it will
   continue execution.
2) Will turn verbose, 'any key' and test mode on.
3) Will make 'informational beep' and continue.
4) Will search for Direct3D processes. Will continue if nothing was found.
   Will prompt user to press 'any key' if process was found and then exit.
5) Will search for OpenGL processes with software rendering using 'simple'
   method. Will continue if nothing was found. Will prompt user to press 
   'any key' if process was found and then exit.
6) Will turn 'any key' and test mode off.
7) Will search for process with name similar to "Skype" using lowercase
   compare. Will prompt user to press 'enter' if nothing was found and then
   exit. Will kill process and prompt user to press 'enter' if process was
   found and then exit.
