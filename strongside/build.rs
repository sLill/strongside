fn main() {
    if cfg!(target_os = "windows") {
        cc::Build::new()
            .file("syscalls/syscalls_mem.c")
            .include("syscalls")
            .compile("syscalls_c");

        cc::Build::new()
            .file("syscalls/syscalls_mem.asm")
            .compile("syscalls_asm");
        println!("cargo:rerun-if-changed=syscalls/");
    }
}
