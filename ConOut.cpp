#include "ConOut.h"
#include "Extras.h"
#include <fcntl.h>	//_setmode
#include <io.h>		//_setmode
#include <iostream>

extern pAttachConsole fnAttachConsole;

int Win32WcostreamBuf::console_attached=0;

Win32WcostreamBuf::Win32WcostreamBuf(bool is_wcout):
	obuf(), active(false), is_wcout(is_wcout), orig_mode(-1), orig_buf(NULL), stdstream_type(NONE), 
	hstdstream(INVALID_HANDLE_VALUE), mb_buf(), mb_caption(), mb_attached(false)
{
	setp(obuf, obuf+W32WBUF_OBUFLEN);
}

Win32WcostreamBuf::~Win32WcostreamBuf()
{
	Deactivate();
}

Win32WcostreamBuf::int_type Win32WcostreamBuf::overflow(Win32WcostreamBuf::int_type ch)
{
	//Not checking validness of pointers because virtual members that can directly affect them are not implemented
	if (WriteBuffer())
		return ch==traits_type::eof()?traits_type::not_eof(ch):sputc(traits_type::to_char_type(ch));
	else
		return traits_type::eof();
}

int Win32WcostreamBuf::sync()
{
	return WriteBuffer()?0:-1;
}

bool Win32WcostreamBuf::Activate()
{
	if (active)
		return false;	

	if ((hstdstream=GetStdHandle(is_wcout?STD_OUTPUT_HANDLE:STD_ERROR_HANDLE))!=INVALID_HANDLE_VALUE) {
		DWORD conmode;
		DWORD filetype=GetFileType(hstdstream);
		if (filetype==FILE_TYPE_UNKNOWN) {	
			//Stdstream is going nowhere (or not valid) - try to attach parent console
			if (!console_attached&&fnAttachConsole&&fnAttachConsole(ATTACH_PARENT_PROCESS)) {
				//Console attached but maybe unusable
				console_attached++;
				if (GetConsoleMode(hstdstream, &conmode)) {
					//We are the first to succesfully attach console so clear the screen and things will look prettier
					ClearScreen();
					stdstream_type=GUICON;
				} else
					stdstream_type=BADCON;
			}
		} else if (filetype==FILE_TYPE_DISK||filetype==FILE_TYPE_PIPE)	
			//Stdstream is redirected to file or pipe
			stdstream_type=REDIR;		
		else if (GetConsoleMode(hstdstream, &conmode)) {
			//Stdstream is a console
			if (console_attached) {
				console_attached++;
				stdstream_type=GUICON;	//We are using console attached elsewhere
			} else
				stdstream_type=CON;		//We are using own console
		} else
			//Stdstream is generic "character device" or undefined but valid file type
			stdstream_type=GEN;
	}
	
	if (stdstream_type!=CON&&stdstream_type!=GUICON) {
		//Will prevent stdout/stderr failing on Cyrillic and Ideographic wide character output (console still have to support them)
		//Warning: this will also break output of sbcs/mbcs characters (only wstring and wchar_t now allowed)
		//_O_U16TEXT is UTF-16 w/o BOM
		fflush(is_wcout?stdout:stderr);
		orig_mode=_setmode(_fileno(is_wcout?stdout:stderr), _O_U16TEXT);
	}
	
	if (is_wcout)
		orig_buf=std::wcout.rdbuf(this);
	else
		orig_buf=std::wcerr.rdbuf(this);
	
	active=true;
	
	return true;
}

bool Win32WcostreamBuf::Deactivate()
{
	if (!active)
		return false;
	
	mb_attached=false;
	mb_buf.clear();
	
	sync();
	
	if (is_wcout)
		std::wcout.rdbuf(orig_buf);
	else
		std::wcerr.rdbuf(orig_buf);
	
	if (orig_mode!=-1) {
		fflush(is_wcout?stdout:stderr);
		_setmode(_fileno(is_wcout?stdout:stderr), orig_mode);
		orig_mode=-1;
	}
	
	//The gentelmen rule: if you are using attached console or merely unsuccesfully attached it - it's your responsibility to free it if no one needs it anymore
	if (stdstream_type==GUICON||stdstream_type==BADCON) {
		if (!--console_attached) {
			//Hack for attached parent console that makes things prettier
			//Parent console will wait for ENTER keystroke after the last WriteConsole
			//Sending it manually so user won't have to do it
			if (stdstream_type==GUICON)
				SimulateEnterKey();
			FreeConsole();
		}
	}
	
	stdstream_type=NONE;
	
	active=false;
	
	return true;
}

bool Win32WcostreamBuf::AttachMessageBox(const wchar_t* caption)
{
	if (!caption||mb_attached)
		return false;
	
	mb_caption=caption;
	mb_attached=true;
	
	return true;
}

bool Win32WcostreamBuf::ShowMessageBox()
{
	if (!mb_attached||!active)
		return false;
	
	sync();
	MessageBox(NULL, mb_buf.c_str(), mb_caption.c_str(), MB_OK|MB_ICONWARNING|MB_SETFOREGROUND);
	mb_buf.clear();
	
	return true;
}

bool Win32WcostreamBuf::WriteBuffer()
{
	if (!active)
		return false;
	
	//Not checking validness of pointers and data length because virtual members that can directly affect them are not implemented
	size_t datalen=pptr()-pbase();
	if (datalen) {
		//Widechar console output causes a shitstorm of issues on Win32
		//First of all, _O_U16TEXT mode is a must on stdout handle or wcout will fail on first unicode character
		//But unfortunately even if wcout not failing now, output to console is crappy most time
		//Unicode characters may be shown incorrectly, there may be spaces after each of output characters or only the very first character of all output will be displayed
		//The only safe way to do widechar console output is using native Win32 function - WriteConsole
		//For redirected output wcout is still ok and even better than WriteFile - it will not mangle new lines
		if (stdstream_type==GUICON||stdstream_type==CON) {
			DWORD written;		
			//If GUICON/CON - hstdstream is guaranteed to be valid
			if (!WriteConsole(hstdstream, pbase(), datalen, &written, NULL)||written!=datalen)
				return false;
		} else {
			//Using fwrite(stdout) instead of wcout
			if (fwrite(pbase(), sizeof(wchar_t), datalen, is_wcout?stdout:stderr)!=datalen)
				return false;
			fflush(is_wcout?stdout:stderr);
		}
		//If we have MessageBox output active - write data to it's buffer
		if (mb_attached)
			mb_buf.append(pbase(), datalen);
		pbump(-datalen);
	}

	return true;
}

void Win32WcostreamBuf::SimulateEnterKey()
{
	//Unfortunately, can't use SendInput here because it sends keystrokes not to app's own window but to currently active window
	LPARAM lParam=MapVirtualKeyEx(VK_RETURN, MAPVK_VK_TO_VSC, GetKeyboardLayout(0))<<16&0x00FF0000;
	PostMessage(GetConsoleWindow(), WM_KEYDOWN, VK_RETURN, lParam|0x00000001);
	Sleep(0);	//This will force current thread to relinquish the remainder of it's time slice so WM_KEYUP will not be send in the same time slice as WM_KEYDOWN
	PostMessage(GetConsoleWindow(), WM_KEYUP, VK_RETURN, lParam|0xC0000001);
}

void Win32WcostreamBuf::ClearScreen()
{
	DWORD ret_len;
	CONSOLE_SCREEN_BUFFER_INFO csbi; 

	if (GetConsoleScreenBufferInfo(hstdstream, &csbi))
		if (FillConsoleOutputCharacter(hstdstream, L' ', csbi.dwSize.X*csbi.dwSize.Y, {0, 0}, &ret_len))					//Fill with blanks
			if (FillConsoleOutputAttribute(hstdstream, csbi.wAttributes, csbi.dwSize.X*csbi.dwSize.Y, {0, 0}, &ret_len))	//Set character attributes for all the blanks
				SetConsoleCursorPosition(hstdstream, {0, 0});
}
