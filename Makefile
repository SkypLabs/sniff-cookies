CC=gcc
CFLAGS=-Wall
LDFLAGS=-lpcap
EXEC=sniff_cookies

all: $(EXEC)

$(EXEC): $(EXEC).o mypcap.o sniff_cookies_lib.o
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)
clean:
	rm -rf *.o
mrproper: clean
	rm -rf $(EXEC)
