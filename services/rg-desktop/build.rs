fn main() {
    // Automatically enable the `devtools` Cargo feature for debug builds.
    // Release builds must opt in explicitly via `--features devtools`.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile == "debug" {
        println!("cargo:rustc-cfg=feature=\"devtools\"");
    }
    tauri_build::build();
}
