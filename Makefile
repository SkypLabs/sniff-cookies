CC=gcc

BDIR=build
INCDIR=include
SRCDIR=src

CFLAGS=-Wall -I$(INCDIR)
LDFLAGS=-lpcap

EXEC=sniff_cookies

all: setup $(EXEC)

$(EXEC): $(BDIR)/$(EXEC).o $(BDIR)/mypcap.o $(BDIR)/sniff_cookies_lib.o
	$(CC) -o $@ $^ $(LDFLAGS)
$(BDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
setup:
	mkdir -p build
clean:
	rm -rf build
mrproper: clean
	rm -rf $(EXEC)
