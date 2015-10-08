# Usage:
# make CC=COMPILER cmd
#	Builds SnK with console output (SnK.exe)
# make CC=COMPILER wnd
#	Builds windowless SnK with dialog output (SnKh.exe)
# make CC=COMPILER
#	Makes both versions of SnK
# make CC=COMPILER clean
#	Cleans directory of executables
# make DEBUG=1
#	Makes debug build

# Conditionals
ifneq ($(CC),x86_64-w64-mingw32-g++)
ifneq ($(CC),i686-w64-mingw32-g++)
ifneq ($(CC),g++)
ifneq ($(CC),clang++)
$(info Compiler not selected! Please set CC variable.)
$(info Possible CC values: x86_64-w64-mingw32-g++, i686-w64-mingw32-g++, g++, clang++)
$(error CC not set)
endif
endif
endif
endif

ifdef DEBUG
	_DEBUG=-DDEBUG	
endif

# Common section
RM=rm -f
CFLAGS=-std=c++11 -Wno-write-strings -D_WIN32_WINNT=0x0502 -DNOMINMAX $(_DEBUG)
LDFLAGS=-lpsapi -lversion -static-libgcc -static-libstdc++
#COMMON_SRC=SnK.cpp ProcessUsage.cpp Killers.cpp Extra.cpp Help.cpp Controller.cpp
COMMON_SRC=SnK.cpp Extra.cpp Help.cpp ProcessUsage.cpp

# Target specific section
CMD_CFLAGS=
WND_CFLAGS=-DHIDDEN
CMD_LDFLAGS=
WND_LDFLAGS=-mwindows
CMD_SRC=$(COMMON_SRC)
WND_SRC=$(COMMON_SRC) ConRedirection.cpp
CMD_OBJ=$(CMD_SRC:.cpp=_cmd.o)
WND_OBJ=$(WND_SRC:.cpp=_wnd.o)
CMD_EXE=SnK.exe
WND_EXE=SnKh.exe

all: cmd wnd
.PHONY: all clean
.INTERMEDIATE: $(CMD_OBJ) $(WND_OBJ)

cmd: $(CMD_SRC) $(CMD_EXE)

wnd: $(WND_SRC) $(WND_EXE)

$(CMD_EXE): $(CMD_OBJ) 
	$(CC) -o $@ $(CMD_OBJ) $(LDFLAGS) $(CMD_LDFLAGS)
	
$(WND_EXE): $(WND_OBJ) 
	$(CC) -o $@ $(WND_OBJ) $(LDFLAGS) $(WND_LDFLAGS)

%_cmd.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) $(CMD_CFLAGS)
	
%_wnd.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) $(WND_CFLAGS)

clean:
	$(RM) *.exe
