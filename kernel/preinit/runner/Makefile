CC = zig cc
SRC = runner.c
TARGET = runner_binary
DUMP = runner_xxd.h

ZIG_VER := $(shell zig version)

CFLAGS += -target aarch64-linux -std=gnu23
CFLAGS += -Oz -flto -s
CFLAGS += -fno-unwind-tables -fmerge-all-constants
CFLAGS += -Wl,--entry=__start
CFLAGS += -s -Wl,--gc-sections,-z,norelro
CFLAGS += -Wno-int-conversion -Wno-unknown-attributes -Wno-macro-redefined

CFLAGS += -DZIG_VERSION=\"$(ZIG_VER)\"

all: $(TARGET) $(DUMP)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@
	#@if command -v upx >/dev/null 2>&1; then upx --ultra-brute $(TARGET); fi

$(DUMP): $(TARGET)
	xxd -i $(TARGET) > $@
	rm -f $(TARGET)

clean:
	rm -f $(TARGET) > /dev/null 2>&1
	rm -f $(DUMP) > /dev/null 2>&1

.PHONY: all clean
