.POSIX:
.PHONY: boot

QEMU_EXTRA_FLAGS=

ARCH=riscv64
RUST_FLAGS=-L. -g -C opt-level=z --edition 2021 --target $(ARCH).json -C relocation-model=static
RUST_SRC=$(RUST_SYSROOT)/lib/rustlib/src/rust/library
OBJCOPY=llvm-objcopy

include cfg.mk

all: cfg.mk krnl.bin

cfg.mk: configure
	@printf 'Run ./configure before make\n'
	@false

libcore.rlib:
	$(RUSTC) $(RUST_FLAGS) --crate-type rlib --crate-name core $(RUST_SRC)/core/src/lib.rs -o $@
libcompiler_builtins.rlib: libcore.rlib compiler_builtins.rs
	$(RUSTC) $(RUST_FLAGS) --crate-type rlib --crate-name compiler_builtins compiler_builtins.rs -o $@
liballoc.rlib: libcore.rlib libcompiler_builtins.rlib
	$(RUSTC) $(RUST_FLAGS) --crate-type rlib --crate-name alloc $(RUST_SRC)/alloc/src/lib.rs -o $@ --cfg no_global_oom_handling

init: libcore.rlib libcompiler_builtins.rlib liballoc.rlib init.rs abi.rs fdt.rs
	$(RUSTC) $(RUST_FLAGS) --crate-type bin --crate-name init init.rs -C link-arg=-Tinit.$(ARCH).lds -o $@

init.bin: init
	$(OBJCOPY) -O binary init $@
	

SRCS=krnl.rs riscv64.rs con.rs rwlock.rs abi.rs

krnl: libcore.rlib libcompiler_builtins.rlib init.bin $(SRCS)
	$(RUSTC) $(RUST_FLAGS) --crate-type bin --crate-name krnl krnl.rs -C link-arg=-T$(ARCH).lds -o $@

krnl.bin: krnl
	$(OBJCOPY) -O binary krnl $@

qemu: krnl.bin
	qemu-system-$(ARCH) -M virt \
	-serial mon:stdio -nographic -net none -cpu max \
	-kernel krnl.bin $(QEMU_EXTRA_FLAGS) -append "init=/toybox console=ttyS0" \
	-smp 2

qemu.efi:
	qemu-system-$(ARCH) -M virt \
	-drive if=pflash,unit=0,format=raw,file=fw/$(ARCH).fd \
	-serial mon:stdio -nographic -net noce -cpu max -s -smp 2

boot: krnl.bin
	cp krnl.bin boot

qemu.uboot.s: boot
	qemu-system-$(ARCH) -M virt \
	-kernel fw/riscv64.u-boot-s.bin \
	-serial mon:stdio -nographic -net none -cpu max \
	-drive file=fat:rw:boot,if=virtio \
	-m 256M -s

qemu.uboot: boot
	qemu-system-$(ARCH) -M virt \
	-bios fw/riscv64.u-boot.bin \
	-serial mon:stdio -nographic -net none -cpu max \
	-drive file=fat:rw:boot,if=virtio \
	-m 256M -s

fmt:
	rustfmt krnl.rs
	rustfmt init.rs

clean:
	rm -f *.d
	rm -f *.rlib
	rm -f krnl.bin
	rm -f krnl
	rm -f init.bin
	rm -f init
