.PHONY: all clean

SOURCES_CRYPTO := $(shell echo *.c)
HEADERS_CRYPTO := $(shell echo *.h)
OBJECTS_CRYPTO := $(patsubst %.c,%.o, $(SOURCES_CRYPTO)) CryptoNight.o keccak.o
TARGET_CRYPTO := libcryptonight.so
TARGET_CRYPTO_STATIC := libcryptonight_s.a
CFLAGS := -O3 -fPIC -maes

all: $(TARGET_CRYPTO) $(TARGET_CRYPTO_STATIC)

%.o: %.c %.h
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: %.cpp %.h
	$(CXX) -c $(CFLAGS) -o $@ $<

$(TARGET_CRYPTO): $(OBJECTS_CRYPTO)
	$(CXX) $(CFLAGS) -std=c++11 -shared $^ -o $@

$(TARGET_CRYPTO_STATIC): $(OBJECTS_CRYPTO)
	$(AR) -crv $@ $^

clean:
	rm -rf $(OBJECTS_CRYPTO) $(TARGET_CRYPTO) $(TARGET_CRYPTO_STATIC)
