#ifndef CONOUT_H
#define CONOUT_H

#include <windows.h>
#include <string>
#include <vector>
#include <streambuf>
#include <functional>

//Buffer size for basic_streambuf in characters
//Keep it reasonable - if it's nearing LONG_MAX you definetely doing it wrong
#define W32WBUF_OBUFLEN 4096

class Win32WcostreamBuf: private std::basic_streambuf<wchar_t> {
	typedef std::function<void(const std::wstring&)> AoutCallbackType;
public:
	enum WCType:char {WCOUT=1, WCERR=2, WCLOG=3};
private:
	enum OutType:char {NONE, REDIR, GEN, CON, GUICON, BADCON};
	//NONE - we basically have nowhere to output stdstream
	//REDIR - stdstream is redirected to file
	//GEN - stdstream goes to some generic device
	//CON - have own console
	//GUICON - succesfully attached parent console
	//BADCON - attached parent console is unusable
	
	static int console_attached;
	
	wchar_t obuf[W32WBUF_OBUFLEN];
	bool active;
	bool enabled;
	WCType wc_type;
	std::wstreambuf *orig_buf;
	OutType stdstream_type;
	HANDLE hstdstream;
	AoutCallbackType aout_proc;
	std::wstring aout_buf;
	
	bool WriteBuffer();
	void ClearScreen();
	void SimulateEnterKey();
	
	virtual int_type overflow(int_type ch);
	virtual int sync();
public:
	Win32WcostreamBuf(WCType wc_type);
	~Win32WcostreamBuf();
	
	bool Activate();
	bool AttachAdditionalOutput(AoutCallbackType aout);
	bool DetachAdditionalOutput();
	void OutputEnabled(bool value);
	bool CallAdditionalOutput();
	bool Deactivate();
};

#endif //CONOUT_H
