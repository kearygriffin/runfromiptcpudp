export CC := gcc
export INCS +=
export LIBS +=
export CFLAGS += -ggdb3 -Wall -Wextra -Wno-long-long -pipe
export CFLAGSSO = $(CFLAGS) -ldl -lc -shared -rdynamic -fpic
#export OTHFLAGS = -W -O2 -D_GNU_SOURCE -fPIC
export OTHFLAGS = -W -O2 -fPIC

export I_USR_LIB = /usr/local/lib
export I_USR_BIN = /usr/local/bin
export I_SUDOERD = /etc/sudoers.d
export I_sudopermit_f = permit-ifconfigtap0updown-user

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

install:	all
#	(Re)write sudoer permit file - be certain it contains only what we expect.
	/bin/echo -e "user\tALL=NOPASSWD:\t/sbin/ifconfig tap0 down\t, /sbin/ifconfig tap0 up"	>  $(I_SUDOERD)/$(I_sudopermit_f)
	/bin/echo -e "user\tALL=NOPASSWD:\t/sbin/ip link set tap0 down\t, /sbin/ip link set tap0 up"	>> $(I_SUDOERD)/$(I_sudopermit_f)
	chmod 0440 $(I_SUDOERD)/$(I_sudopermit_f)
	cp -avu  runfromiptcpudp.so $(I_USR_LIB)
	cp -avu runfromiptcpudp    $(I_USR_BIN)
