fn main() {
    println!("cargo:rerun-if-changed=src/child/target_capture.c");
    cc::Build::new()
        .file("src/child/target_capture.c")
        .flag("-std=c11")
        .compile("sigrund_target_capture");
    println!("cargo:rerun-if-changed=src/child/setup.c");
    cc::Build::new()
        .file("src/child/setup.c")
        .flag("-std=c11")
        .warnings_into_errors(true)
        .compile("sigrund_child");
}
