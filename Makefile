MODE=release
ARCH=riscv64
# ARCH=x86_64

.PHONY: hello.elf

all: krnl.elf init.elf

include util/$(ARCH).mk
TARGET=../util/$(_T).json
CARGO_FLAGS=-Zbuild-std -Zbuild-std-features=compiler-builtins-mem --target=$(TARGET)

# K_RFLAGS=-C link-args=--image-base=0xffffffc000000000 -Cforce-frame-pointers=yes
H_RFLAGS=-C link-args=--image-base=0xffffffff80000000 -Cforce-frame-pointers=yes
hello.elf:
	cd hello; RUSTFLAGS='$(H_RFLAGS)' cargo build $(CARGO_FLAGS)
	cp hello/target/$(_T)/debug/hello hello.elf

fsd.elf.release:
	cd fsd; RUSTFLAGS='-C target-feature=+crt-static -C link-args=--sysroot=/usr/riscv64-linux-musl/ -C link-args=-v -C link-arg=/usr/lib/clang/14.0.1/lib/linux/libclang_rt.builtins-riscv64.a -C link-args=--target=riscv64-linux-musl' cargo build --target=riscv64-linux-musl.json -Zbuild-std --release
fsd.elf.debug:
	cd fsd; RUSTFLAGS='-C target-feature=+crt-static -C link-args=--sysroot=/usr/riscv64-linux-musl/ -C link-args=-v -C link-arg=/usr/lib/clang/14.0.1/lib/linux/libclang_rt.builtins-riscv64.a -C link-args=--target=riscv64-linux-musl' cargo build --target=riscv64-linux-musl.json -Zbuild-std
# fsd.elf: fsd.elf.$(MODE)
# 	cp fsd/target/riscv64-linux-musl/$(MODE)/fsd fsd.elf
# fsd.elf: fsd.elf.$(MODE)
# 	cp fsd/target/riscv64-linux-musl/$(MODE)/fsd fsd.elf


# fsd.elf: fsd.elf.debug
# 	cp fsd/target/riscv64-linux-musl/debug/fsd fsd.elf

# fsd.elf: fsd.elf.temp
# 	cp fsd.elf.temp fsd.elf

fsd.elf:
	cp toybox fsd.elf

fsd.elf.temp: fsd-temp/main.c
	cc --target=riscv64-linux-musl --sysroot=/usr/riscv64-linux-musl fsd-temp/main.c -o fsd.elf.temp -static

initrd.tar: fsd.elf
	tar -cf initrd.tar fsd.elf

vdso.so.debug:
	cd vdso; cargo build --target=riscv64gc-unknown-none-elf -Zbuild-std
	
init.elf.debug:
	cd init; RUSTFLAGS='-Cforce-frame-pointers=yes' cargo build $(CARGO_FLAGS)
init.elf.release:
	cd init; RUSTFLAGS='-Cforce-frame-pointers=yes' cargo build $(CARGO_FLAGS) --release
init.elf: init.elf.$(MODE)
	cp init/target/$(_T)/$(MODE)/init init.elf
init.fmt:
	cd init; cargo fmt

K_RFLAGS=-C link-args=--image-base=0xffffffc000000000 -Cforce-frame-pointers=yes
krnl.elf.debug: init.elf
	cd krnl; RUSTFLAGS='$(K_RFLAGS)' cargo build $(CARGO_FLAGS)
krnl.elf.release: init.elf
	cd krnl; RUSTFLAGS='$(K_RFLAGS)' cargo build $(CARGO_FLAGS) --release
krnl.elf: krnl.elf.$(MODE)
	cp krnl/target/$(_T)/$(MODE)/krnl krnl.elf
krnl.fmt:
	cd krnl; cargo fmt
# krnl.map: krnl.elf
# 	nm -C krnl.elf > krnl.map

boot.elf.debug: krnl.elf
	cd boot; cargo build $(CARGO_FLAGS)
boot.elf.release: krnl.elf
	cd boot; cargo build $(CARGO_FLAGS) --release
boot.elf: boot.elf.$(MODE)
	cp boot/target/$(_T)/$(MODE)/boot boot.elf
boot.fmt:
	cd boot; cargo fmt

fmt: boot.fmt krnl.fmt init.fmt

qemu: boot.elf initrd.tar
	qemu-system-riscv64 -kernel boot.elf -serial mon:stdio -nographic -m 1024 -M virt -vga virtio -initrd initrd.tar -append init=/sbin/init

uqemu: hello.elf
	cp /usr/share/limine/BOOTX64.EFI qemu/
	cp hello.elf qemu/
	qemu-system-x86_64 -hda fat:rw:qemu \
	-bios ~/Documents/Programming/oslo/fw/x64/OVMF.fd \
	-net none -kernel qemu/BOOTX64.EFI -serial mon:stdio \
	-enable-kvm -m 1024 --no-reboot -d int -D qemulog.log
