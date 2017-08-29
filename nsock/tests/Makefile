#
# nsock regression test suite
# Same license as nmap -- see https://nmap.org/book/man-legal.html
##

NBASEDIR=/home/default/nmap/nbase
NSOCKLIB=../src/libnsock.a
NBASELIB=$(NBASEDIR)/libnbase.a

CC 	= /home/default/third_party/llvm-build/Release+Asserts/bin/clang
CPPFLAGS = -I/home/default/nmap/libpcap  -I/home/default/nmap/nbase -I../include
CFLAGS	= -ggdb -O0 -fsanitize=memory -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,trace-gep -DHAVE_GETADDRINFO=1 -Wall 
LDFLAGS	= -L/home/default/nmap/libpcap -fsanitize=memory -L/home/default/nmap/nbase
LIBS	= -lssl -lcrypto /home/default/nmap/libpcap/libpcap.a 

SRC = tests_main.c \
      basic.c \
      timer.c \
      logs.c \
      connect.c \
      ghlists.c \
      ghheaps.c \
      cancel.c

OBJ = $(SRC:.c=.o)

EXE = tests_main

all: $(SRC) $(EXE)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@ $(NSOCKLIB) $(NBASELIB) $(LIBS)

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $< -o $@

clean:
	$(RM) $(OBJ) $(EXE)

rebuild: clean $(EXE)

.PHONY: clean rebuild
