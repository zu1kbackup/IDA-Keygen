CC=diet gcc
XCC=i686-w64-mingw32-gcc
XLD=i686-w64-mingw32-ld
XAR=i686-w64-mingw32-ar
XNM=i686-w64-mingw32-nm
XRANLIB=i686-w64-mingw32-ranlib
XDLLTOOL=i686-w64-mingw32-dlltool
XOBJDUMP=i686-w64-mingw32-objdump
XSTRIP=i686-w64-mingw32-strip
XAS=i686-w64-mingw32-as
XDLLTOOL=i686-w64-mingw32-dlltool
XDLLWRAP=i686-w64-mingw32-dllwrap
LC_ALL=C
SED=sed

FLAGS = -Wall -Wno-pointer-sign
CFLAGS = -O2 $(FLAGS) -Wno-strict-aliasing
XCFLAGS = -DMINGW $(FLAGS) -mno-ms-bitfields

INC =

all:	key patch

key:	../ida_key ../ida_key.exe
patch:  ../patch_ida ../patch_ida.exe
anon:	../anon_idb ../anon_idb.exe

IDA_OBJ = ida_key.o md5.o base64.o bigint.o
IDA_XOBJ = ida_key.obj md5.obj base64.obj bigint.obj

PATCH_OBJ = patch_ida.o
PATCH_XOBJ = patch_ida.obj

ANON_OBJ = anon_idb.o
ANON_XOBJ = anon_idb.obj

.INTERMEDIATE: $(IDA_OBJ) $(IDA_XOBJ) $(PATCH_OBJ) $(PATCH_XOBJ) $(ANON_OBJ) $(ANON_XOBJ)

%.o: %.c $(INC)
	$(CC) $(CFLAGS) -c $< -o $@

%.obj: %.c $(INC)
	$(XCC) $(XCFLAGS) -c $< -o $@

pack:	ida_key
	upx --best $^

../ida_key: $(IDA_OBJ)
	$(CC) -s $(CFLAGS) -o $@ $^
	strip --strip-all $@

../ida_key.exe: $(IDA_XOBJ)
	$(XCC) -s $(XCFLAGS) -o $@ $^
	$(XSTRIP) --strip-all $@

../patch_ida: $(PATCH_OBJ)
	$(CC) -s -O2 -o $@ $^
	strip --strip-all $@

../patch_ida.exe: $(PATCH_XOBJ)
	$(XCC) $(XCFLAGS) -mwindows -o $@ $^
	$(XSTRIP) --strip-all $@

anon_idb.c: ../anon_idb.h

../anon_idb: $(ANON_OBJ)
	$(CC) -s -O2 -o $@ $^
	strip --strip-all $@

../anon_idb.exe: $(ANON_XOBJ)
	$(XCC) $(XCFLAGS) -mwindows -o $@ $^
	$(XSTRIP) --strip-all $@

clean:
	rm -f *~ *.a
