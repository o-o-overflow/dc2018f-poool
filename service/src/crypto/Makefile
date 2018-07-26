.PHONY: clean

SOURCES_CRYPTO := $(shell echo *.c)
HEADERS_CRYPTO := $(shell echo *.h)
OBJECTS_CRYPTO := $(patsubst %.c,%.o, $(SOURCES_CRYPTO))
TARGET_CRYPTO := libcryptonight.so
CFLAGS := -O3 -fPIC -maes

%.o: %.c %.h
	$(CC) -c $(CFLAGS) -o $@ $<

$(TARGET_CRYPTO): $(OBJECTS_CRYPTO) CryptoNight.cpp keccak.cpp
	$(CXX) $(CFLAGS) -std=c++11 -shared $^ -o $@

clean:
	rm -rf $(OBJECTS_CRYPTO) $(TARGET_CRYPTO)
