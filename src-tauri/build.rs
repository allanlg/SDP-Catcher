fn main() {
    // 1. Setup Windows Attributes for UAC Administrator privileges
    let mut attrs = tauri_build::Attributes::new();
    attrs = attrs.windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("admin.manifest")),
    );

    // 2. Setup Npcap SDK linking
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let npcap_arch = match target_arch.as_str() {
        "x86_64" => Some("x64"),
        "aarch64" => Some("ARM64"),
        "x86" => None,
        unsupported => panic!("unsupported Windows architecture: {unsupported}"),
    };
    let mut npcap_lib = std::path::PathBuf::from(dir).join("npcap-sdk").join("Lib");
    if let Some(npcap_arch) = npcap_arch {
        npcap_lib = npcap_lib.join(npcap_arch);
    }
    println!("cargo:rustc-link-search=native={}", npcap_lib.display());

    // 3. Trigger build with attributes
    tauri_build::try_build(attrs).expect("failed to build tauri-app");
}
