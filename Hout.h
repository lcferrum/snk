#ifndef HOUT_H
#define HOUT_H

#include <string.h>

namespace Hout {
	//"PADDING"     "STR STR STR STR STR
	//              STR STR STR STR STR 
	//              STR STR"
	//^---INDENT---^
	//^----------TERMINAL_SIZE----------^
	//If INDENT>=TERMINAL_SIZE: wcout<<PADDING<<STR<<endl
	void Paragraph(const wchar_t* str, size_t indent=0, const wchar_t* padding=NULL);
	
	//              "STR STR STR"FFFFFFFF
	//^---INDENT---^
	//^----------TERMINAL_SIZE----------^
	//If INDENT>=TERMINAL_SIZE: wcout<<STR<<endl
	void Separator(const wchar_t* str, size_t indent=0, wchar_t filler=L'\0');
	
	//wcout<<endl
	void EmptyLine();

	void SetTerminalSize(size_t size);
	size_t GetTerminalSize();
};

#endif // HOUT_H
