.POSIX:

ARCH=riscv64
RUST_FLAGS=-O --edition 2021 --target $(ARCH).json -C relocation-model=static
RUST_SRC=$(RUST_SYSROOT)/lib/rustlib/src/rust/library

include cfg.mk

all: cfg.mk libcompiler_builtins.rlib

cfg.mk: configure
	@printf 'Run ./configure before make\n'
	@false

libcore.rlib:
	$(RUSTC) $(RUST_FLAGS) --crate-type rlib --crate-name libcore $(RUST_SRC)/core/src/lib.rs -o $@
libcompiler_builtins.rlib: compiler_builtins.rs
	$(RUSTC) $(RUST_FLAGS) --crate-type rlib --crate-name compiler_builtins compiler_builtins.rs -o $@

qemu:
	qemu-system-$(ARCH) -M virt \
	-serial mon:stdio -nographic -net none -cpu max \
	-kernel boot/$(ARCH)/boot.bin

qemu.efi:
	qemu-system-$(ARCH) -M virt \
	-drive if=pflash,unit=0,format=raw,file=fw/$(ARCH).fd \
	-serial mon:stdio -nographic -net none -cpu max

clean:
	rm -f *.d
	rm -f *.rlib
