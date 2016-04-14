#include "Hout.h"
#include <algorithm>
#include <iostream>
#include <iomanip>

namespace Hout {
	size_t terminal_size=79;		//Default terminal size for Win32 = 80 columns (79 characters + 1 new-line symbol)
}

void Hout::Paragraph(const wchar_t* str, size_t indent, const wchar_t* padding)
{
	if (indent>=terminal_size) {
		std::wcout<<(padding?padding:L"")<<str<<std::endl;
		return;
	}

	size_t paragraph_width=terminal_size-indent;
	size_t break_point;
	std::wstring output=str;

	for (;;) {
		if (output.length()<=paragraph_width) {
			std::wcout<<std::setw(indent)<<std::right<<(padding?std::wstring(padding, std::min(indent, wcslen(padding))):L"")<<std::setw(paragraph_width)<<std::left<<output<<std::endl;
			break;
		} else {
			if ((break_point=output.rfind(L' ', paragraph_width-1))==std::wstring::npos) break_point=paragraph_width;
				else break_point++;
			std::wcout<<std::setw(indent)<<std::right<<(padding?std::wstring(padding, std::min(indent, wcslen(padding))):L"")<<std::setw(paragraph_width)<<std::left<<output.substr(0, break_point)<<std::endl;
			output.erase(0, break_point);
		}
		if (padding) padding=NULL;
	}
}

void Hout::Separator(const wchar_t* str, size_t indent, wchar_t filler)
{
	if (indent>=terminal_size) {
		std::wcout<<str<<std::endl;
		return;
	}

	std::wstring padding(indent, L' ');
	std::wstring output=str;
	output.resize(terminal_size-indent, filler);
	std::wcout<<padding<<output.c_str()<<std::endl;	//Passing as c_str() so excessing NULLs will be omitted
}

void Hout::EmptyLine()
{
	std::wcout<<std::endl;
}

void Hout::SetTerminalSize(size_t size)
{
	//Windows console will move every characters that doesn't fit in console width to the next line, including new-line symbol
	//So we should reserve one last character for the new-line symbol
	if (size)
		terminal_size=size-1;
	else
		terminal_size=0;		
}

size_t Hout::GetTerminalSize()
{
	return terminal_size;
}
