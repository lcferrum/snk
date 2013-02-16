#include <windows.h>
#include <sstream>
#include <iostream>

std::stringstream cout_buf;
std::streambuf *p_cout_bak;

void CaptureCout() {
	p_cout_bak=NULL;
	p_cout_bak=std::cout.rdbuf(cout_buf.rdbuf());
}

void ReleaseCout() {
	if (p_cout_bak) std::cout.rdbuf(p_cout_bak);
}

std::string GetCoutBuf() {
	if (p_cout_bak) return cout_buf.str();
		else return "";
}
