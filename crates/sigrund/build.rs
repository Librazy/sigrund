fn main() {
    println!("cargo:rerun-if-changed=src/child/setup.c");
    cc::Build::new()
        .file("src/child/setup.c")
        .flag("-std=c11")
        .warnings_into_errors(true)
        .compile("sigrund_child");
}
