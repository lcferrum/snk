# Usage:
# make CC=COMPILER cmd
#	Builds SnK with console output (SnK.exe)
# make CC=COMPILER wnd
#	Builds windowless SnK with dialog output (SnKh.exe)
# make CC=COMPILER
#	Makes both versions of SnK
# make clean
#	Cleans directory of executables
# make upx
#	Pack executables with upx
# make UPSTREAM_INC=PATH
#	Change include path for clang++/g++ (default is /c/cygwin/usr/i686-w64-mingw32/sys-root/mingw/include/)
# make USE_CYCLE_TIME=1
#	Uses process cycle time instead kernel/user time (available from Win 7)
# make DEBUG=LEVEL
#	Makes debug build

# Conditionals
ifeq (,$(if $(filter-out upx clean,$(MAKECMDGOALS)),,$(MAKECMDGOALS)))
ifeq (,$(filter $(CC),i686-w64-mingw32-g++ x86_64-w64-mingw32-g++ g++ clang++))
$(info Compiler not selected! Please set CC variable.)
$(info Possible CC values: x86_64-w64-mingw32-g++, i686-w64-mingw32-g++, g++, clang++)
$(error CC not set)
endif
endif

ifdef DEBUG
	override DEBUG:=-DDEBUG=$(DEBUG)
endif

ifdef USE_CYCLE_TIME
ifneq ($(USE_CYCLE_TIME),0)
	override USE_CYCLE_TIME=-DUSE_CYCLE_TIME
else
	override USE_CYCLE_TIME=
endif
endif

# Common section
RM=rm -f
UPX=upx
CFLAGS=-std=c++11 -Wno-write-strings -D_WIN32_WINNT=0x0502 -DNOMINMAX -DUNICODE -D_UNICODE $(DEBUG) $(USE_CYCLE_TIME)
LDFLAGS=-lversion -lole32 -static-libgcc -static-libstdc++ -s
COMMON_SRC=SnK.cpp Extras.cpp Common.cpp Hout.cpp Killers.cpp ProcessUsage.cpp FilePathRoutines.cpp Controller.cpp ConOut.cpp AsmPatches.S
UPSTREAM_INC=/c/cygwin/usr/i686-w64-mingw32/sys-root/mingw/include/

# Compiler specific section
ifeq ($(CC),x86_64-w64-mingw32-g++)
	LDFLAGS+=-municode
	WNDSUBSYS=-mwindows
endif
ifeq ($(CC),i686-w64-mingw32-g++)
	LDFLAGS+=-municode
	WNDSUBSYS=-mwindows
endif
# Extra options for outdated clang++/g++ with upstream includes to generate binaries compatible with Win 9x/NT4
# i386 is minimum system requirement for Windows 95 (MinGW 4.7.2 default arch)
# i486 is minimum system requirement for Windows NT4
# It's assumed that g++ (MinGW) version is 4.7.2, clang++ (LLVM) version is 3.6.2 and includes are from MinGW-w64 4.9.2
ifeq ($(CC),clang++)
	INC=-I$(UPSTREAM_INC)
	CFLAGS+=-target i486-pc-windows-gnu -march=i486 -Wno-ignored-attributes -Wno-deprecated-register -Wno-inconsistent-dllimport -DUMDF_USING_NTSTATUS -DOBSOLETE_WMAIN
	WNDSUBSYS=-Wl,--subsystem,windows
	ifndef DEBUG
		CFLAGS+=-Wno-unused-value
	endif
endif
ifeq ($(CC),g++)
	INC=-I$(UPSTREAM_INC)
	CFLAGS+=-Wno-attributes -DUMDF_USING_NTSTATUS -DOBSOLETE_WMAIN
	WNDSUBSYS=-mwindows
endif

# Target specific section
CMD_CFLAGS=
WND_CFLAGS=-DHIDDEN
CMD_LDFLAGS=
WND_LDFLAGS=$(WNDSUBSYS)
CMD_SRC=$(COMMON_SRC)
WND_SRC=$(COMMON_SRC)
CMD_OBJ=$(patsubst %.S,%_cmd.o,$(patsubst %.cpp,%_cmd.o,$(CMD_SRC)))
WND_OBJ=$(patsubst %.S,%_wnd.o,$(patsubst %.cpp,%_wnd.o,$(WND_SRC)))
CMD_EXE=SnK.exe
WND_EXE=SnKh.exe

.PHONY: all clean upx
.INTERMEDIATE: $(CMD_OBJ) $(WND_OBJ)

all: cmd wnd

cmd: $(CMD_SRC) $(CMD_EXE)

wnd: $(WND_SRC) $(WND_EXE)

$(CMD_EXE): $(CMD_OBJ) 
	$(CC) -o $@ $(CMD_OBJ) $(LDFLAGS) $(CMD_LDFLAGS)
	
$(WND_EXE): $(WND_OBJ) 
	$(CC) -o $@ $(WND_OBJ) $(LDFLAGS) $(WND_LDFLAGS)

%_cmd.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) $(CMD_CFLAGS) $(INC)
	
%_cmd.o: %.S
	$(CC) -c -o $@ $< $(CFLAGS) $(CMD_CFLAGS) $(INC)
	
%_wnd.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) $(WND_CFLAGS) $(INC)
	
%_wnd.o: %.S
	$(CC) -c -o $@ $< $(CFLAGS) $(WND_CFLAGS) $(INC)
	
upx:
	$(UPX) $(CMD_EXE) $(WND_EXE) ||:

clean:
	$(RM) $(CMD_EXE) $(CMD_OBJ) $(WND_EXE) $(WND_OBJ) ||:
