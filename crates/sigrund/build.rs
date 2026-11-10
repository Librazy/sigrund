fn main() {
    println!("cargo:rerun-if-changed=src/child/launcher_abi.h");
    let header = std::fs::read_to_string("src/child/launcher_abi.h").unwrap();
    let mut rust = String::new();
    let mut c_layout = Vec::new();
    let mut rust_layout = Vec::new();
    let mut current_rust = String::new();
    let mut current_c = String::new();
    for line in header.lines() {
        if let Some(body) = line
            .strip_prefix("SG_STRUCT(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let names: Vec<_> = body.split(',').map(str::trim).collect();
            let name = names[0];
            current_rust = name.to_owned();
            current_c = names[1].to_owned();
            c_layout.extend([
                format!("sizeof(struct {current_c})"),
                format!("_Alignof(struct {current_c})"),
            ]);
            rust_layout.extend([
                format!("std::mem::size_of::<{name}>()"),
                format!("std::mem::align_of::<{name}>()"),
            ]);
            rust.push_str(&format!("#[repr(C)]\nstruct {name} {{\n"));
        } else if let Some(body) = line
            .strip_prefix("SG_FIELD(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let fields: Vec<_> = body.splitn(3, ',').collect();
            rust.push_str(&format!("{}: {},\n", fields[0].trim(), fields[1].trim()));
            c_layout.push(format!(
                "offsetof(struct {current_c}, {})",
                fields[0].trim()
            ));
            rust_layout.push(format!(
                "std::mem::offset_of!({current_rust}, {})",
                fields[0].trim()
            ));
        } else if line == "SG_END" {
            rust.push_str("}\n");
        } else if line.starts_with("#define SG_") && !line.contains('(') {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() == 3 && fields[2].parse::<u32>().is_ok() {
                rust.push_str(&format!("const {}: u32 = {};\n", fields[1], fields[2]));
            }
        }
    }
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    rust.push_str(&format!("#[cfg(test)] #[test] fn launcher_abi_layout_matches_native() {{ unsafe extern \"C\" {{ fn sigrund_launcher_layout(index: usize) -> usize; }} let expected = [{}]; for (index, value) in expected.iter().enumerate() {{ assert_eq!(*value, unsafe {{ sigrund_launcher_layout(index) }}); }} }}\n", rust_layout.join(",")));
    let probe = output.join("launcher_abi_probe.c");
    std::fs::write(&probe, format!("#include <stdint.h>\n#include <stddef.h>\n#include \"launcher_abi.h\"\nsize_t sigrund_launcher_layout(size_t index) {{ static const size_t values[] = {{{}}}; return index < sizeof(values)/sizeof(values[0]) ? values[index] : (size_t)-1; }}\n", c_layout.join(","))).unwrap();
    cc::Build::new()
        .file(probe)
        .include("src/child")
        .flag("-std=c11")
        .warnings_into_errors(true)
        .compile("sigrund_launcher_abi_probe");
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("launcher_abi.rs"),
        rust,
    )
    .unwrap();

    println!("cargo:rerun-if-changed=src/child/namespace_filter.h");
    println!("cargo:rerun-if-changed=src/child/filter_probe.c");
    cc::Build::new()
        .file("src/child/filter_probe.c")
        .warnings_into_errors(true)
        .compile("sigrund_filter_probe");
    println!("cargo:rerun-if-changed=src/child/lsm.c");
    cc::Build::new()
        .file("src/child/lsm.c")
        .warnings_into_errors(true)
        .compile("sigrund_lsm");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rerun-if-changed=src/child/peer_auth.c");
    println!("cargo:rerun-if-changed=src/child/client_anchor.c");
    cc::Build::new()
        .file("src/child/client_anchor.c")
        .file("src/child/peer_auth.c")
        .flag("-std=c11")
        .warnings_into_errors(true)
        .compile("sigrun_client_anchor");
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
