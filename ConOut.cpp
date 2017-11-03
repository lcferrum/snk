#include "ConOut.h"
#include "Externs.h"
#include <fcntl.h>	//_setmode
#include <io.h>		//_setmode
#include <iostream>

extern pAttachConsole fnAttachConsole;
extern pGetConsoleWindow fnGetConsoleWindow;

int Win32WcostreamBuf::console_attached=0;

Win32WcostreamBuf::Win32WcostreamBuf(WCType wc_type):
	obuf(), active(false), enabled(true), wc_type(wc_type), orig_buf(NULL), stdstream_type(NONE), 
	hstdstream(INVALID_HANDLE_VALUE), tee_buf(NULL)
{
	setp(obuf, obuf+W32WBUF_OBUFLEN-1);	//-1 is for quick version of LF->CRLF conversion where LF just terminates buffer
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

void Win32WcostreamBuf::OutputEnabled(bool value)
{
	sync();
	enabled=value;
}

bool Win32WcostreamBuf::Activate(std::wstring *new_tee_buf)
{
	if (active) return false;

	if ((hstdstream=GetStdHandle(wc_type==WCOUT?STD_OUTPUT_HANDLE:STD_ERROR_HANDLE))!=INVALID_HANDLE_VALUE) {
		DWORD conmode;
		DWORD filetype=GetFileType(hstdstream);
		if (filetype==FILE_TYPE_UNKNOWN) {	
			//Stdstream is going nowhere (or not valid) - try to attach parent console
			//The trick is that console is attached to the process and not to the standard handle
			//So if someone already succesfully attached a console - GetFileType will return FILE_TYPE_CHAR for any valid handle
			//It is observed that if someone already called AttachConsole(ATTACH_PARENT_PROCESS) and it returned TRUE - next calls (was actual attach succesfull or not) will return FALSE
			//That's why we are also checking console_attached counter - don't try to attach console if someone already tried and failed (indicated by FILE_TYPE_UNKNOWN with console_attached!=0)
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
		} else if (filetype==FILE_TYPE_DISK||filetype==FILE_TYPE_PIPE) {
			//Stdstream is redirected to file or pipe
			stdstream_type=REDIR;		
		} else if (GetConsoleMode(hstdstream, &conmode)) {
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
	
	switch (wc_type) {
		case WCOUT:
			orig_buf=std::wcout.rdbuf(this);
			break;
		case WCERR:
			orig_buf=std::wcerr.rdbuf(this);
			break;
		case WCLOG:
			orig_buf=std::wclog.rdbuf(this);
			break;
	}
	
	active=true;
	
	tee_buf=new_tee_buf;
	
	return true;
}

bool Win32WcostreamBuf::Deactivate()
{
	if (!active) return false;
	
	sync();	
	tee_buf=NULL;
	
	switch (wc_type) {
		case WCOUT:
			std::wcout.rdbuf(orig_buf);
			break;
		case WCERR:
			std::wcerr.rdbuf(orig_buf);
			break;
		case WCLOG:
			std::wclog.rdbuf(orig_buf);
			break;
	}

	//The gentelmen rule: if you are using attached console or merely unsuccesfully attached it - it's your responsibility to free it if no one needs it anymore
	if (stdstream_type==GUICON||stdstream_type==BADCON) {
		if (!--console_attached) {
			//It is guaranteed by the Activate algorithm that if console attach was unsuccesfull - there won't be second tries
			//And console is attached to the process and not to the standard handle
			//So there can be only one BADCON object and it won't mix with GUICON/CON objects
			//And if there is one GUICON/CON object - every other object will also be GUICON/CON (respectively)
			//That's why even with out-of-order deactivation, check below will return true for truly the last of GUICON objects
			//There can't be the case when only one object is GUICON and other is something else - every other object will also be GUICON
			if (stdstream_type==GUICON)
				//Hack for attached parent console that makes things prettier
				//Parent console will wait for ENTER keystroke after the last WriteConsole
				//Sending it manually so user won't have to do it
				SimulateEnterKey();
			FreeConsole();
		}
	}
	
	stdstream_type=NONE;
	
	active=false;
	
	return true;
}

bool Win32WcostreamBuf::WriteBuffer()
{
	//Not checking validness of pointers and data length because virtual members that can directly affect them are not implemented
	ptrdiff_t datalen=pptr()-pbase();
	if (datalen) {
		if (enabled) {
			//Widechar console output causes a shitstorm of issues on Win32
			//First of all, _O_U16TEXT mode is a must on stdout handle or wprintf/fwrite(stdout) will fail on first unicode character (we don't do it because stdout is completely bypassed here)
			//Second, even though wcout uses stdout in underlying code, with it's default streambuf on Win32 it will convert all output to some MBCS codepage before writing it to stdout
			//And there is nothing you can do about it, short of supplying own streambuf (exactly what we are doing)
			//Third, all stdout output in standard Win32 C/C++ libs implementation comes down to calling internally write(stdout) from MSVCRT that automatically changes LF to CRLF
			//Only it has a bug on early implementations (before Vista) where it doesn't distinguish widechar version of LF from single char LF and just adds single byte CR before every encountered LF byte
			//Finally, whatever is used internally in stdout when it is connected to console (and not redirected to file/pipe) - it's definetely not WriteConsoleW and there will be some nasty underlying UTF16->MBCS conversion involved
			//In the end, the only safe way to do widechar console output on Win32 is using own streambuf where:
			//	Unredirected output (where stdout is connected to actual console) uses native Win32 UNICODE vesrion of WriteConsole (WriteConsoleW)
			//	Redirected output (where stdout is connected to file/pipe) uses native Win32 WriteFile and handles LF->CRLF converson on it's own
			
			if (stdstream_type==GUICON||stdstream_type==CON) {
				//Because we are building app in UNICODE, WriteConsole is alias for WriteConsoleW here
				//WriteConsoleW is used here just to emphasize that it is indeed widechar console output
				DWORD written;		
				if (!WriteConsoleW(hstdstream, pbase(), datalen, &written, NULL)||written!=datalen)
					return false;
			} else if (stdstream_type==REDIR||stdstream_type==GEN) {				
				//Count number of LF appearances
				DWORD lf_cnt=0;
				wchar_t* obuf_iter=pbase();
				while (obuf_iter!=pptr()) lf_cnt+=L'\n'==*obuf_iter++;	//true casted to int is always 1 by C++ standard
				
				DWORD cnv_size=(lf_cnt+datalen)*sizeof(wchar_t);
				wchar_t* crlf_buf=NULL;
				wchar_t* cnv_buf=pbase();
				
				//Fast version of LF->CRLF conversion - buffer just terminated with LF
				if (lf_cnt==1&&*(pptr()-1)==L'\n') {
					//It is guaranteed that pptr() points to valid memory location because setp was called with pend=obuf+W32WBUF_OBUFLEN-1
					//Hack below assumes that wchar_t is UTF16 LE
					//0x000A000D is represented in memory as L"\r\n" (CRLF) on LE platforms
					//On Windows wchar_t is indeed UTF16 LE (even for versions of NT that run on bi-endian platforms)
					//But by C++ standard wchar_t is implementation defined so, just in case, test that we really dealing with 2 byte wchar_t
					static_assert(sizeof(wchar_t)==2, L"sizeof(wchar_t) should be exactly 2 bytes");
					*(DWORD*)(pptr()-1)=0x000A000D;
				//Standard version of LF->CRLF conversion
				} else if (lf_cnt) {
					wchar_t* crlf_iter=cnv_buf=crlf_buf=new wchar_t[cnv_size];
					wchar_t crlf_char;
					obuf_iter=pbase();
					while (obuf_iter!=pptr()) {
						crlf_char=*obuf_iter++;
						if (crlf_char==L'\n') *crlf_iter++=L'\r';
						*crlf_iter++=crlf_char;
					}
				}
				//No LF->CRLF conversion is required
				
				DWORD written;
				BOOL write_ok=WriteFile(hstdstream, cnv_buf, cnv_size, &written, NULL);
				delete[] crlf_buf;
				if (!write_ok||written!=cnv_size)
					return false;
			}
			
			//If we have tee buffer enabled - write data to it
			if (tee_buf)
				tee_buf->append(pbase(), datalen);
		}
		pbump(-datalen);
	}

	return true;
}

void Win32WcostreamBuf::SimulateEnterKey()
{
	//Unfortunately, can't use SendInput here because it sends keystrokes not to app's own window but to currently active window
	if (fnGetConsoleWindow) {
		LPARAM lParam=MapVirtualKeyEx(VK_RETURN, MAPVK_VK_TO_VSC, GetKeyboardLayout(0))<<16&0x00FF0000;
		PostMessage(fnGetConsoleWindow(), WM_KEYDOWN, VK_RETURN, lParam|0x00000001);
		Sleep(0);	//This will force current thread to relinquish the remainder of it's time slice so WM_KEYUP will not be send in the same time slice as WM_KEYDOWN
		PostMessage(fnGetConsoleWindow(), WM_KEYUP, VK_RETURN, lParam|0xC0000001);
	}
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
