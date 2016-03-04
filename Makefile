export CC := gcc
export INCS +=
export LIBS +=
export CFLAGS += -ggdb3 -Wall -Wextra -Wno-long-long -pipe
export CFLAGSSO = $(CFLAGS) -ldl -lc -shared -rdynamic -fpic
#export OTHFLAGS = -W -O2 -D_GNU_SOURCE -fPIC
export OTHFLAGS = -W -O2 -fPIC

export I_USR_LIB = /usr/local/lib
export I_USR_BIN = /usr/local/bin

runfromiptcpudp.so:	runfromiptcpudp.c
	$(CC) $(CFLAGSSO) $(OTHFLAGS) -Wl,-soname,$@ -o $@ $(basename $@).c
	strip $@
	chmod a+rx $@
	chmod a+rx $(basename $@)

#.PHONY: all
#all:	runfromiptcpudp.so

#.PHONY: clean
#clean:
#	@rm -f *.a *.o *.so* $(PRJ)-*.rpm $(PRJ)-*-*-*.tgz $(PRJ)-*.tar.gz

all: $(I_USR_LIB)/runfromiptcpudp.so $(I_USR_BIN)/runfromiptcpudp

$(I_USR_LIB)/runfromiptcpudp.so: runfromiptcpudp.so
	sudo cp -avu  runfromiptcpudp.so $(I_USR_LIB)

$(I_USR_BIN)/runfromiptcpudp:
	sudo cp -avu runfromiptcpudp    $(I_USR_BIN)

#install:	all
#	cp -avu  runfromiptcpudp.so $(I_USR_LIB)
#	cp -avu runfromiptcpudp    $(I_USR_BIN)
