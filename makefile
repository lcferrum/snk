# Usage:
# make BUILD=COMPILER HOST=OS_TYPE cmd
#	Builds SnK with console output (SnK.exe)
# make BUILD=COMPILER HOST=OS_TYPE wnd
#	Builds windowless SnK with dialog output (SnKh.exe)
# make BUILD=COMPILER HOST=OS_TYPE
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
ifeq (,$(and $(filter $(BUILD),MinGW-w64 MinGW-w64_pthreads MinGW_472 Clang_362),$(filter $(HOST),x86-64 x86)))
$(info Compiler and/or OS type is invalid! Please correctly set BUILD and HOST variables.)
$(info Possible BUILD values: MinGW-w64, MinGW-w64_pthreads, MinGW_472, Clang_362)
$(info Possible HOST values: x86-64, x86)
$(error BUILD/HOST is invalid)
endif
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
CFLAGS=-std=c++11 -Wno-write-strings -D_WIN32_WINNT=0x0502 -DNOMINMAX -DUNICODE -D_UNICODE $(USE_CYCLE_TIME)
LDFLAGS=-lversion -lole32 -static-libgcc -static-libstdc++ -Wl,--enable-stdcall-fixup
COMMON_SRC=SnK.cpp Extras.cpp Common.cpp Hout.cpp Killers.cpp ProcessUsage.cpp FilePathRoutines.cpp Controller.cpp ConOut.cpp AsmPatches.S Res.rc
UPSTREAM_INC=/c/cygwin/usr/i686-w64-mingw32/sys-root/mingw/include/

# Debug specific common section
ifdef DEBUG
	CFLAGS+=-DDEBUG=$(DEBUG) -g
	LDFLAGS+=-g
else
	CFLAGS+=-O2
	LDFLAGS+=-O2 -s
endif

# Compiler/OS specific sections
# N.B.:
# i386 is minimum system requirement for Windows 95, maximum arch for apps is pentium2 (OS doesn't handle SSE instructions without patch)
# i486 is minimum system requirement for Windows NT4, maximum arch for apps is pentium2 (OS doesn't handle SSE instructions)
# pentium is minimum system requirement for Windows 2000

# MinGW 4.7.2 with includes from current MinGW-w64
# i386 is MinGW 4.7.2 default arch
ifeq ($(BUILD),MinGW_472)
	CC=g++
	INC=-I$(UPSTREAM_INC)
	CFLAGS+=-Wno-attributes -DUMDF_USING_NTSTATUS -DOBSOLETE_WMAIN
	WNDSUBSYS=-mwindows
	WINDRES=windres
ifeq ($(HOST),x86-64)
$(error not implemented)
endif
ifeq ($(HOST),x86)
endif
endif

# Current MinGW-w64 with Win32 threads
# MinGW-w64 minimum supported target 32-bit Windows version is Windows 2000
# pentiumpro is MinGW-w64 default arch for 32-bit compiler
ifeq ($(BUILD),MinGW-w64)
	LDFLAGS+=-municode
	WNDSUBSYS=-mwindows
ifeq ($(HOST),x86-64)
	CC=x86_64-w64-mingw32-g++
	WINDRES=x86_64-w64-mingw32-windres
endif
ifeq ($(HOST),x86)
	CC=i686-w64-mingw32-g++
	WINDRES=i686-w64-mingw32-windres
endif
endif

# Current MinGW-w64 with POSIX threads
# MinGW-w64 minimum supported target 32-bit Windows version is Windows 2000
# pentiumpro is MinGW-w64 default arch for 32-bit compiler
ifeq ($(BUILD),MinGW-w64_pthreads)
	LDFLAGS+=-static -lpthread -municode
	WNDSUBSYS=-mwindows
ifeq ($(HOST),x86-64)
	CC=x86_64-w64-mingw32-g++
	WINDRES=x86_64-w64-mingw32-windres
endif
ifeq ($(HOST),x86)
	CC=i686-w64-mingw32-g++
	WINDRES=i686-w64-mingw32-windres
endif
endif

# Clang 3.6.2 with includes from current MinGW-w64
# pentium4 is Clang 3.6.2 default arch
ifeq ($(BUILD),Clang_362)
	CC=clang++
	INC=-I$(UPSTREAM_INC)
	CFLAGS+=-target i486-pc-windows-gnu -march=i486 -Wno-ignored-attributes -Wno-deprecated-register -Wno-inconsistent-dllimport -DUMDF_USING_NTSTATUS -DOBSOLETE_WMAIN
	WNDSUBSYS=-Wl,--subsystem,windows
	WINDRES=windres
	ifndef DEBUG
		CFLAGS+=-Wno-unused-value
	endif
ifeq ($(HOST),x86-64)
$(error not implemented)
endif
ifeq ($(HOST),x86)
endif
endif

# Target specific section
CMD_CFLAGS=
WND_CFLAGS=-DHIDDEN
CMD_LDFLAGS=
WND_LDFLAGS=$(WNDSUBSYS)
CMD_SRC=$(COMMON_SRC)
WND_SRC=$(COMMON_SRC)
CMD_OBJ=$(patsubst %.S,%_cmd.o,$(patsubst %.cpp,%_cmd.o,$(patsubst %.rc,%_cmd.o,$(CMD_SRC))))
WND_OBJ=$(patsubst %.S,%_wnd.o,$(patsubst %.cpp,%_wnd.o,$(patsubst %.rc,%_wnd.o,$(WND_SRC))))
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
	
%_cmd.o: %.rc
	$(WINDRES) $< $@ $(filter -D% -U% -I%,$(CFLAGS) $(CMD_CFLAGS)) $(INC)
	
%_wnd.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) $(WND_CFLAGS) $(INC)
	
%_wnd.o: %.S
	$(CC) -c -o $@ $< $(CFLAGS) $(WND_CFLAGS) $(INC)
	
%_wnd.o: %.rc
	$(WINDRES) $< $@ $(filter -D% -U% -I%,$(CFLAGS) $(WND_CFLAGS)) $(INC)
	
upx:
	$(UPX) $(CMD_EXE) $(WND_EXE) ||:

clean:
	$(RM) $(CMD_EXE) $(CMD_OBJ) $(WND_EXE) $(WND_OBJ) ||:
