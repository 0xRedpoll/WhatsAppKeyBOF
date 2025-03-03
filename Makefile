BOFNAME := WhatsAppKeyBOF
COMINCLUDE := 
LIBINCLUDE := -l shlwapi -l crypt32 -l iostream
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

all: deps
all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c bof.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c bof.c -DBOF

test:
	$(CC_x64) bof.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) bof.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

scanbuild:
	$(CC) bof.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction $(COMINCLUDE) --platform=win64 bof.c

deps:
	python3 -m pip install -r requirements.txt

clean:
	rm $(BOFNAME).*.exe