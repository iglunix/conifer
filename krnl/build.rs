fn main() {
    println!("cargo:rerun-if-changed=riscv64.ld");
    println!("cargo:rustc-link-arg=-Triscv64.ld");
}
