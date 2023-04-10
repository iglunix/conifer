.POSIX:

include cfg.mk

RUST_TARGET=riscv64.json
C_TARGET=riscv64-linux-musl

RUSTC=rustc
RUSTC_FLAGS=-Lout --edition 2021 --target $(RUST_TARGET)
RUST_LIBS=out/libcompiler_builtins.rlib out/libcore.rlib

out/boot.elf: boot/main.rs $(RUST_LIBS) out/libcon.rlib boot/riscv64.ld out/krnl.elf out/libelf.rlib out/libfdt.rlib
	rustc $(RUSTC_FLAGS) boot/main.rs --crate-name boot -C link-arg="-Tboot/riscv64.ld" -o $@

out/krnl.elf: krnl/main.rs $(RUST_LIBS) out/libcon.rlib out/libfdt.rlib out/liballoc.rlib
	rustc $(RUSTC_FLAGS) krnl/main.rs --crate-name krnl -C link-arg="--image-base=0xffffffc000000000" -o $@

out/libelf.rlib: $(RUST_LIBS) lib/elf.rs
	rustc $(RUSTC_FLAGS) --crate-type rlib lib/elf.rs --crate-name elf -o $@

out/libcon.rlib: $(RUST_LIBS) lib/con.rs
	rustc $(RUSTC_FLAGS) --crate-type rlib lib/con.rs --crate-name con -o $@

out/libfdt.rlib: $(RUST_LIBS) lib/fdt.rs
	rustc $(RUSTC_FLAGS) --crate-type rlib lib/fdt.rs --crate-name fdt -o $@

out/libcompiler_builtins.rlib: out/libcore.rlib lib/compiler_builtins.rs
	rustc $(RUSTC_FLAGS) --crate-type rlib lib/compiler_builtins.rs --crate-name compiler_builtins -o $@

out/libcore.rlib:
	rustc $(RUSTC_FLAGS) --crate-type rlib /usr/lib/rustlib/src/rust/library/core/src/lib.rs --crate-name core -o $@

out/liballoc.rlib: out/libcore.rlib
	rustc $(RUSTC_FLAGS) --crate-type rlib /usr/lib/rustlib/src/rust/library/alloc/src/lib.rs --crate-name alloc -o $@

qemu: out/boot.elf
	qemu-system-riscv64 -kernel out/boot.elf -nographic -m 2048
