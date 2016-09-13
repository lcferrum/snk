#ifndef HOUT_H
#define HOUT_H

#include <string>

namespace Hout {
	//"PADDING"     "STR STR STR STR STR
	//              STR STR STR STR STR 
	//              STR STR"
	//^---INDENT---^
	//^----------TERMINAL_SIZE----------^
	//If INDENT>=TERMINAL_SIZE: wcout<<PADDING<<STR<<endl
	void Paragraph(const wchar_t* str, std::wstring::size_type indent=0, const wchar_t* padding=NULL);
	
	//              "STR STR STR"FFFFFFFF
	//^---INDENT---^
	//^----------TERMINAL_SIZE----------^
	//If INDENT>=TERMINAL_SIZE: wcout<<STR<<endl
	void Separator(const wchar_t* str, std::wstring::size_type indent=0, wchar_t filler=L'\0');
	
	//wcout<<endl
	void EmptyLine();

	void SetTerminalSize(std::wstring::size_type size);
	std::wstring::size_type GetTerminalSize();
};

#endif // HOUT_H
