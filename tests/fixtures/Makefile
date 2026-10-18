# Purpose-built targets for the gdb_plus test suite.
# Built automatically by tests/conftest.py (make -C tests/fixtures). Every test looks
# locations up by symbol, so rebuilding with another compiler must not break anything.

CC      ?= gcc
CFLAGS  := -O0 -g -fno-stack-protector -fcf-protection=none -fno-omit-frame-pointer -Isrc
BIN     := bin

NATIVE  := basic basic_nopie forking execs signals threads tracer sysemu_tracer
I386    := basic_i386 forking_i386 execs_i386 signals_i386 threads_i386 tracer_i386

# Foreign architectures, run under qemu-user. There is usually no cross libc installed, so these are
# freestanding static binaries (src/freestanding.h) built with clang + lld, which target every arch.
CROSS_CC     ?= clang
CROSS_ARCHES := arm aarch64 riscv32 riscv64 mips mips64
CROSS_FLAGS  := -O0 -g -fno-stack-protector -fno-omit-frame-pointer -Isrc -DFREESTANDING \
                -ffreestanding -fno-builtin -nostdlib -static -fuse-ld=lld -Wl,--entry=_start -w
triple_arm     := --target=armv7-linux-gnueabihf -marm
triple_aarch64 := --target=aarch64-linux-gnu
triple_riscv32 := --target=riscv32-linux-gnu
triple_riscv64 := --target=riscv64-linux-gnu
triple_mips    := --target=mips-linux-gnu -fno-pic -mno-abicalls
triple_mips64  := --target=mips64-linux-gnuabi64 -fno-pic -mno-abicalls

all: native i386 cross

native: $(addprefix $(BIN)/,$(NATIVE))

# Needs gcc-multilib. Failing here only skips the i386 tests.
i386: $(addprefix $(BIN)/,$(I386))

$(BIN):
	mkdir -p $(BIN)

$(BIN)/basic: src/basic.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -pie -fPIE -o $@ $<

$(BIN)/basic_nopie: src/basic.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -no-pie -fno-pie -o $@ $<

$(BIN)/basic_i386: src/basic.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -m32 -no-pie -fno-pie -o $@ $<

$(BIN)/threads: src/threads.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -pthread -o $@ $<

$(BIN)/threads_i386: src/threads.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -m32 -pthread -o $@ $<

$(BIN)/%_i386: src/%.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -m32 -o $@ $<

$(BIN)/%: src/%.c src/labels.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# Needs clang and lld. Each arch is built on its own: a failure only skips the tests of that arch.
CROSS_FIXTURES := basic signals

cross:
	-@for arch in $(CROSS_ARCHES); do for name in $(CROSS_FIXTURES); do $(MAKE) -s $(BIN)/$${name}_$$arch; done; done

# The same runtime on x86-64, to check freestanding.h without QEMU
$(BIN)/basic_freestanding: src/basic.c src/labels.h src/freestanding.h | $(BIN)
	$(CROSS_CC) --target=x86_64-linux-gnu $(CROSS_FLAGS) -fcf-protection=none -o $@ $<

$(BIN)/basic_%: src/basic.c src/labels.h src/freestanding.h | $(BIN)
	$(CROSS_CC) $(triple_$*) $(CROSS_FLAGS) -o $@ $<

$(BIN)/signals_%: src/signals.c src/labels.h src/freestanding.h | $(BIN)
	$(CROSS_CC) $(triple_$*) $(CROSS_FLAGS) -o $@ $<

clean:
	rm -rf $(BIN)

.PHONY: all native i386 cross clean
