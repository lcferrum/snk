#include <iostream>

void PrintUsage() {
	std::cout<<
#ifndef HIDDEN
"Usage: SnK [settings_block|swith[:parametres][=argument]] ...\n"
"\n"
"This is a usage quick reference. Please check README.TXT for more information.\n"
	<<std::endl;
	std::cout<<
"Switches:"
	<<std::endl;
	std::cout<<
"/hlp                          Print this help and exit."
	<<std::endl;
	std::cout<<
"/ver                          Print version information and exit."
	<<std::endl;
	std::cout<<
"/bpp                          Make standart Windows 'informational beep' and\n"
"                              continue execution."
	<<std::endl;
	std::cout<<
"/sec                          Secured execution. Will exit program if there is\n"
"                              another instance already running that has\n"
"                              executed this switch."
	<<std::endl;
	std::cout<<
"/cpu                          Kill process with highest cpu load."
	<<std::endl;
	std::cout<<
"/d3d[:simple][:soft]          Kill process that uses Direct3D and has highest\n"
"                              cpu load."
	<<std::endl;
	std::cout<<
"/ogl[:simple][:soft]          Kill process that uses OpenGL and has highest cpu\n"
"                              load."
	<<std::endl;
	std::cout<<
"/d2d[:simple][:strict]        Kill process that uses DirectDraw and has highest\n"
"                              cpu load."
	<<std::endl;
	std::cout<<
"/gld[:simple][:strict]        Kill process that uses Glide and has highest cpu\n"
"                              load."
	<<std::endl;
	std::cout<<
"/inr[:manual|:ghost]          Kill process that is not responding and has\n"
"                              highest cpu load."
	<<std::endl;
	std::cout<<
"/fsc[:apps][:strict]          Kill process that is running in fullscreen and\n"
"                              has highest cpu load."
	<<std::endl;
	std::cout<<
"/pth[:full][:lcase]=NAME      Kill process whose name matches wildcard 'NAME'\n"
"                              and has highest cpu load."
	<<std::endl;
	std::cout<<
"Settings:"
	<<std::endl;
	std::cout<<
"+t|-t                         Will turn test mode on/off."
	<<std::endl;
	std::cout<<
"+v|-v                         Will turn verbose mode on/off."
	<<std::endl;
	std::cout<<
"+k|-k                         Will turn 'any key' mode on/off."
	<<std::endl;
	std::cout<<
"+a|-a                         Will turn 'query all processes' mode on/off."
#else
"Usage: SnKh [settings_block|swith[:parametres][=argument]] ...\n"
"\n"
"Please check README.TXT for more information.\n"
#endif
	<<std::endl;
}

void PrintVersion() {
	std::cout<<
#ifndef HIDDEN
"Search and Kill v 1.0\n"
#else
"Search and Kill (windowless) v 1.0\n"
#endif
"\n"
#ifndef HIDDEN
"Run with /hlp switch for usage information.\n"
#else
"Run with +v /hlp command for usage information.\n"
#endif
"\n"
"Copyright (c) 2012, Lcferrum <lcferrum@yandex.com>\n"
"Licensed under BSD license - see LICENSE.TXT file for details."
#ifdef HIDDEN
"\n"
#endif
	<<std::endl;
}
