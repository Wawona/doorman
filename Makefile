# Makefile for libdoorman + CLI + example + tests.

CC        := xcrun clang
SWIFT     ?= xcrun swiftc
ARCH      ?= $(shell uname -m)
PREFIX    ?= /usr/local

BUILD     := build
OBJ       := $(BUILD)/obj
LIBDIR    := $(BUILD)/lib
BINDIR    := $(BUILD)/bin

STRICT    := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
             -Wcast-qual -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
             -Wformat=2 -Wundef -Wvla -Werror

CFLAGS    := -arch $(ARCH) -O2 -fvisibility=hidden $(STRICT) -Idoorman/include
SHIMS     := doorman/include/doorman_swift_shims.h
SWIFT_FLAGS := -parse-as-library -import-objc-header $(SHIMS) -I doorman/include -I doorman/src -O

LIB_C_SRCS  := doorman/src/util.c doorman/src/backend_pam.c doorman/src/sessions_spawn.c
LIB_SWIFT   := $(wildcard doorman/Sources/*.swift)
LIB_C_OBJS  := $(patsubst doorman/src/%.c,$(OBJ)/%.o,$(LIB_C_SRCS))
LIB_SWIFT_OBJS := $(patsubst doorman/Sources/%.swift,$(OBJ)/%-swift.o,$(LIB_SWIFT))
LIB_OBJS    := $(LIB_C_OBJS) $(LIB_SWIFT_OBJS)

LDFRAME   := -framework Foundation -framework OpenDirectory -framework Security
LDLIBS    := -lpam -lobjc

STATICLIB := $(LIBDIR)/libdoorman.a
DYLIB     := $(LIBDIR)/libdoorman.dylib

TOOLLINKS := useradd userdel passwd groupadd groupdel usermod gpasswd

.PHONY: all lib cli example test install clean tests
all: lib cli example tests

$(OBJ)/%.o: doorman/src/%.c | $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%-swift.o: doorman/Sources/%.swift | $(OBJ)
	$(SWIFT) -c $< $(SWIFT_FLAGS) -o $@

$(OBJ) $(LIBDIR) $(BINDIR):
	@mkdir -p $@

lib: $(STATICLIB) $(DYLIB)

$(STATICLIB): $(LIB_OBJS) | $(LIBDIR)
	xcrun ar rcs $@ $(LIB_OBJS)

$(DYLIB): $(LIB_OBJS) | $(LIBDIR)
	$(CC) $(CFLAGS) -dynamiclib -install_name @rpath/libdoorman.dylib \
		$(LIB_OBJS) $(LDFRAME) $(LDLIBS) -o $@

CLI_SWIFT_FLAGS := -parse-as-library -import-objc-header $(SHIMS) -I doorman/include -I doorman/src -O

CLI_CONV_OBJ := $(OBJ)/cli_conv.o

cli: $(BINDIR)/doorman
$(CLI_CONV_OBJ): cli/cli_conv.c | $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(BINDIR)/doorman: cli/DoormanCLI.swift $(CLI_CONV_OBJ) $(STATICLIB) | $(BINDIR)
	$(SWIFT) cli/DoormanCLI.swift $(CLI_SWIFT_FLAGS) $(CLI_CONV_OBJ) $(STATICLIB) \
		-framework Foundation -framework OpenDirectory -framework Security \
		-Xlinker -lpam -Xlinker -lobjc -o $@
	@for t in $(TOOLLINKS); do ln -sf doorman $(BINDIR)/$$t; done

example: $(BINDIR)/macdm
$(BINDIR)/macdm: examples/macdm/macdm.c $(STATICLIB) | $(BINDIR)
	$(CC) $(CFLAGS) $< $(STATICLIB) $(LDFRAME) $(LDLIBS) -o $@

tests: $(BINDIR)/test_doorman
$(BINDIR)/test_doorman: tests/TestDoorman.swift $(STATICLIB) | $(BINDIR)
	$(SWIFT) tests/TestDoorman.swift -parse-as-library $(CLI_SWIFT_FLAGS) $(STATICLIB) \
		-framework Foundation -framework OpenDirectory -framework Security \
		-Xlinker -lpam -Xlinker -lobjc -o $@

test: tests
	@echo "== unit tests =="
	$(BINDIR)/test_doorman

install: all
	@install -d $(PREFIX)/lib $(PREFIX)/include $(PREFIX)/bin $(PREFIX)/share/doc/doorman
	install -m 0644 $(STATICLIB) $(PREFIX)/lib/
	install -m 0755 $(DYLIB) $(PREFIX)/lib/
	install -m 0644 doorman/include/doorman.h $(PREFIX)/include/
	install -m 0755 $(BINDIR)/doorman $(PREFIX)/bin/
	install -m 0644 LICENSE $(PREFIX)/share/doc/doorman/LICENSE
	@for t in $(TOOLLINKS); do ln -sf doorman $(PREFIX)/bin/$$t; done

clean:
	rm -rf $(BUILD)
