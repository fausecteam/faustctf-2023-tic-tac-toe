.PHONY: all clean cleanall

CC=gcc
CFLAGS=-std=c11 -pedantic -Wall -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -s -D_XOPEN_SOURCE=700
#CFLAGS=-std=c11 -pedantic -Wall -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -s -D_XOPEN_SOURCE=700 -funroll-loops
# -fsanitize=address,undefined
LDFLAGS= -lsqlite3
#OPENSSL=-lcrypto -lssl
WRAPPERFLAGS=-Wl,--wrap=puts

all: tic-tac-toe

tic-tac-toe: wrapper.c utils.c tic.c anti_debugger.c
#	$(CC) $(CFLAGS) $(LDFLAGS) $(OPENSSL) $(WRAPPERFLAGS) -fanalyzer -o $@ $^
	$(CC) $(CFLAGS) $(WRAPPERFLAGS) -o $@ $^ $(LDFLAGS)
	strip -s $@
	strip -s -R .comment -R '.note*' -R '.eh_frame*' -R '.shstrtab' $@
	printf '\x02' | dd conv=notrunc of=./tic-tac-toe bs=1 seek=5
#	echo -ne '\x00\x00\x00\x00\x00\x00\x00\x00'  | dd conv=notrunc of=./tic-tac-toe bs=1 seek=40
#	echo -ne '\x00\x00\x00\x00' | dd conv=notrunc of=./tic-tac-toe bs=1 seek=60

clean:
	rm -f tic-tac-toe

cleanall: clean
	rm -f dsa.sqlite3
