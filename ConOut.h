#ifndef CONOUT_H
#define CONOUT_H

#include <windows.h>
#include <string>
#include <vector>
#include <streambuf>

#define W32WBUF_OBUFLEN 256

class Win32WcostreamBuf: private std::basic_streambuf<wchar_t> {
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
	bool is_wcout;
	int orig_mode;
	std::wstreambuf *orig_buf;
	OutType stdstream_type;
	HANDLE hstdstream;
	std::wstring mb_caption;
	std::wstring mb_buf;
	bool mb_attached;
	
	bool WriteBuffer();
	void ClearScreen();
	void SimulateEnterKey();
	
	virtual int_type overflow(int_type ch);
	virtual int sync();
public:
	Win32WcostreamBuf(bool is_wcout);
	~Win32WcostreamBuf();
	
	bool Activate();
	bool AttachMessageBox(const wchar_t* caption);
	bool ShowMessageBox();
	bool Deactivate();
};

#endif //CONOUT_H
