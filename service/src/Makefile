.PHONY: all clean

SRC := client.c daemon.c job.c json.c utils.c crypto.c
OBJ := $(patsubst %.c,%.o, $(SRC))
CFLAGS += -O3 -fPIE -Wl,-z,relro,-z,now -Wno-unused-result -Wno-multichar -I.

%.o: %.c %.h
	$(CC) -c $(CFLAGS) -o $@ $<

all: poool bench

poool: poool.c $(OBJ) libcryptonight.so
	$(CC) $(CFLAGS) -o $@ $^ -Lcrypto -lcrypto -lpthread -lcryptonight
	strip $@

bench: bench.c crypto.o libcryptonight.so
	$(CC) $(CFLAGS) -o $@ $^ -Lcrypto -lcrypto -lcryptonight

libcryptonight.so:
	make -C crypto
	cp crypto/libcryptonight.so $@
	strip $@

clean:
	rm -rf *.o poool libcryptonight.so crypto/libcryptonight.so
