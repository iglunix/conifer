MODE=release

all: krnl.elf

fsd.elf.debug:
	cd fsd; cargo build --target=riscv64gc-unknown-linux-musl -Zbuild-std

vdso.so.debug:
	cd vdso; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std
	
init.elf.debug:
	cd init; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std
	cp init/target/riscv64gc-unknown-none-elf/debug/init init.elf

init.elf.release:
	cd init; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std --release
	cp init/target/riscv64gc-unknown-none-elf/release/init init.elf

krnl.elf.debug:
	cd krnl; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std
	cp krnl/target/riscv64gc-unknown-none-elf/debug/krnl krnl.elf

krnl.elf.release:
	cd krnl; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std --release
	cp krnl/target/riscv64gc-unknown-none-elf/release/krnl krnl.elf

init.elf: init.elf.$(MODE)

krnl.elf.$(MODE): init.elf

krnl.elf: krnl.elf.$(MODE)

init.fmt:
	cd init; cargo fmt

krnl.fmt:
	cd krnl; cargo fmt

fmt: init.fmt krnl.fmt

qemu: krnl.elf
	qemu-system-riscv64 -kernel krnl.elf -serial mon:stdio -nographic -m 1024
