use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PICOQUIC_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_AUTO_BUILD");
    println!("cargo:rerun-if-env-changed=PICOTLS_INCLUDE_DIR");

    let explicit_paths = has_explicit_picoquic_paths();
    let auto_build = env_flag("PICOQUIC_AUTO_BUILD", true);
    let mut picoquic_include_dir = locate_picoquic_include_dir();
    let mut picoquic_lib_dir = locate_picoquic_lib_dir();
    let mut picotls_include_dir = locate_picotls_include_dir();

    if auto_build
        && !explicit_paths
        && (picoquic_include_dir.is_none() || picoquic_lib_dir.is_none())
    {
        println!("cargo:warning=auto-building picoquic (set PICOQUIC_AUTO_BUILD=0 to disable)");
        build_picoquic()?;
        picoquic_include_dir = locate_picoquic_include_dir();
        picoquic_lib_dir = locate_picoquic_lib_dir();
        picotls_include_dir = locate_picotls_include_dir();
    }

    let picoquic_include_dir = picoquic_include_dir.ok_or(
        "Missing picoquic headers; set PICOQUIC_DIR or PICOQUIC_INCLUDE_DIR (default: vendor/picoquic).",
    )?;
    let picoquic_lib_dir = picoquic_lib_dir.ok_or(
        "Missing picoquic build artifacts; run ./scripts/build_picoquic.sh or set PICOQUIC_BUILD_DIR/PICOQUIC_LIB_DIR.",
    )?;
    let picotls_include_dir = picotls_include_dir.ok_or(
        "Missing picotls headers; set PICOTLS_INCLUDE_DIR or build picoquic with PICOQUIC_FETCH_PTLS=ON.",
    )?;

    let mut object_paths = Vec::with_capacity(1);

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cc_dir = manifest_dir.join("cc");
    let cc_src = cc_dir.join("slipstream_server_cc.c");
    let mixed_cc_src = cc_dir.join("slipstream_mixed_cc.c");
    let poll_src = cc_dir.join("slipstream_poll.c");
    let test_helpers_src = cc_dir.join("slipstream_test_helpers.c");
    let picotls_layout_src = cc_dir.join("picotls_layout.c");
    println!("cargo:rerun-if-changed={}", cc_src.display());
    println!("cargo:rerun-if-changed={}", mixed_cc_src.display());
    println!("cargo:rerun-if-changed={}", poll_src.display());
    println!("cargo:rerun-if-changed={}", test_helpers_src.display());
    println!("cargo:rerun-if-changed={}", picotls_layout_src.display());
    let picoquic_internal = picoquic_include_dir.join("picoquic_internal.h");
    if picoquic_internal.exists() {
        println!("cargo:rerun-if-changed={}", picoquic_internal.display());
    }
    let cc_obj = out_dir.join("slipstream_server_cc.c.o");
    compile_cc(&cc_src, &cc_obj, &picoquic_include_dir)?;
    object_paths.push(cc_obj);

    let mixed_cc_obj = out_dir.join("slipstream_mixed_cc.c.o");
    compile_cc(&mixed_cc_src, &mixed_cc_obj, &picoquic_include_dir)?;
    object_paths.push(mixed_cc_obj);

    let poll_obj = out_dir.join("slipstream_poll.c.o");
    compile_cc(&poll_src, &poll_obj, &picoquic_include_dir)?;
    object_paths.push(poll_obj);

    let test_helpers_obj = out_dir.join("slipstream_test_helpers.c.o");
    compile_cc(&test_helpers_src, &test_helpers_obj, &picoquic_include_dir)?;
    object_paths.push(test_helpers_obj);

    let picotls_layout_obj = out_dir.join("picotls_layout.c.o");
    compile_cc_with_includes(
        &picotls_layout_src,
        &picotls_layout_obj,
        &[&picoquic_include_dir, &picotls_include_dir],
    )?;
    object_paths.push(picotls_layout_obj);

    let archive = out_dir.join("libslipstream_client_objs.a");
    create_archive(&archive, &object_paths)?;
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=slipstream_client_objs");

    let picoquic_libs = resolve_picoquic_libs(&picoquic_lib_dir).ok_or(
        "Missing picoquic build artifacts; run ./scripts/build_picoquic.sh or set PICOQUIC_BUILD_DIR/PICOQUIC_LIB_DIR.",
    )?;
    for dir in picoquic_libs.search_dirs {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    for lib in picoquic_libs.libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=pthread");

    Ok(())
}

fn locate_repo_root() -> Option<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    let crate_dir = Path::new(&manifest_dir);
    Some(crate_dir.parent()?.parent()?.to_path_buf())
}

fn env_flag(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

fn has_explicit_picoquic_paths() -> bool {
    env::var_os("PICOQUIC_DIR").is_some()
        || env::var_os("PICOQUIC_INCLUDE_DIR").is_some()
        || env::var_os("PICOQUIC_BUILD_DIR").is_some()
        || env::var_os("PICOQUIC_LIB_DIR").is_some()
}

fn build_picoquic() -> Result<(), Box<dyn std::error::Error>> {
    let root = locate_repo_root().ok_or("Could not locate repository root for picoquic build")?;
    let script = root.join("scripts").join("build_picoquic.sh");
    if !script.exists() {
        return Err("scripts/build_picoquic.sh not found; run git submodule update --init --recursive vendor/picoquic".into());
    }
    let picoquic_dir = env::var_os("PICOQUIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("vendor").join("picoquic"));
    if !picoquic_dir.exists() {
        return Err("picoquic submodule missing; run git submodule update --init --recursive vendor/picoquic".into());
    }
    let build_dir = env::var_os("PICOQUIC_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".picoquic-build"));

    let status = Command::new(script)
        .env("PICOQUIC_DIR", picoquic_dir)
        .env("PICOQUIC_BUILD_DIR", build_dir)
        .status()?;
    if !status.success() {
        return Err(
            "picoquic auto-build failed (run scripts/build_picoquic.sh for details)".into(),
        );
    }
    Ok(())
}

fn locate_picoquic_include_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("PICOQUIC_INCLUDE_DIR") {
        let candidate = PathBuf::from(dir);
        if has_picoquic_internal_header(&candidate) {
            return Some(candidate);
        }
    }

    if let Ok(dir) = env::var("PICOQUIC_DIR") {
        let candidate = PathBuf::from(&dir);
        if has_picoquic_internal_header(&candidate) {
            return Some(candidate);
        }
        let candidate = Path::new(&dir).join("picoquic");
        if has_picoquic_internal_header(&candidate) {
            return Some(candidate);
        }
    }

    if let Some(root) = locate_repo_root() {
        let candidate = root.join("vendor").join("picoquic").join("picoquic");
        if has_picoquic_internal_header(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn locate_picoquic_lib_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("PICOQUIC_LIB_DIR") {
        let candidate = PathBuf::from(dir);
        if has_picoquic_libs(&candidate) {
            return Some(candidate);
        }
    }

    if let Ok(dir) = env::var("PICOQUIC_BUILD_DIR") {
        let candidate = PathBuf::from(&dir);
        if has_picoquic_libs(&candidate) {
            return Some(candidate);
        }
        let candidate = Path::new(&dir).join("picoquic");
        if has_picoquic_libs(&candidate) {
            return Some(candidate);
        }
    }

    if let Some(root) = locate_repo_root() {
        let candidate = root.join(".picoquic-build");
        if has_picoquic_libs(&candidate) {
            return Some(candidate);
        }
        let candidate = root.join(".picoquic-build").join("picoquic");
        if has_picoquic_libs(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn locate_picotls_include_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("PICOTLS_INCLUDE_DIR") {
        let candidate = PathBuf::from(dir);
        if has_picotls_header(&candidate) {
            return Some(candidate);
        }
    }

    if let Ok(dir) = env::var("PICOQUIC_BUILD_DIR") {
        let candidate = Path::new(&dir)
            .join("_deps")
            .join("picotls-src")
            .join("include");
        if has_picotls_header(&candidate) {
            return Some(candidate);
        }
    }

    if let Ok(dir) = env::var("PICOQUIC_LIB_DIR") {
        let candidate = Path::new(&dir)
            .join("_deps")
            .join("picotls-src")
            .join("include");
        if has_picotls_header(&candidate) {
            return Some(candidate);
        }
        if let Some(parent) = Path::new(&dir).parent() {
            let candidate = parent.join("_deps").join("picotls-src").join("include");
            if has_picotls_header(&candidate) {
                return Some(candidate);
            }
        }
    }

    if let Some(root) = locate_repo_root() {
        let candidate = root
            .join(".picoquic-build")
            .join("_deps")
            .join("picotls-src")
            .join("include");
        if has_picotls_header(&candidate) {
            return Some(candidate);
        }
        let candidate = root
            .join("vendor")
            .join("picoquic")
            .join("picotls")
            .join("include");
        if has_picotls_header(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn has_picoquic_internal_header(dir: &Path) -> bool {
    dir.join("picoquic_internal.h").exists()
}

fn has_picotls_header(dir: &Path) -> bool {
    dir.join("picotls.h").exists()
}

fn has_picoquic_libs(dir: &Path) -> bool {
    resolve_picoquic_libs(dir).is_some()
}

struct PicoquicLibs {
    search_dirs: Vec<PathBuf>,
    libs: Vec<&'static str>,
}

fn resolve_picoquic_libs(dir: &Path) -> Option<PicoquicLibs> {
    if let Some(libs) = resolve_picoquic_libs_single_dir(dir) {
        return Some(PicoquicLibs {
            search_dirs: vec![dir.to_path_buf()],
            libs,
        });
    }

    let mut picotls_dirs = vec![dir.join("_deps").join("picotls-build")];
    if let Some(parent) = dir.parent() {
        picotls_dirs.push(parent.join("_deps").join("picotls-build"));
    }
    for picotls_dir in picotls_dirs {
        if let Some(libs) = resolve_picoquic_libs_split(dir, &picotls_dir) {
            let mut search_dirs = vec![dir.to_path_buf()];
            if picotls_dir != dir && !search_dirs.contains(&picotls_dir) {
                search_dirs.push(picotls_dir);
            }
            return Some(PicoquicLibs { search_dirs, libs });
        }
    }

    if let Some(parent) = dir.parent() {
        if let Some(libs) = resolve_picoquic_libs_split(parent, dir) {
            return Some(PicoquicLibs {
                search_dirs: vec![parent.to_path_buf(), dir.to_path_buf()],
                libs,
            });
        }
        if let Some(grandparent) = parent.parent() {
            if let Some(libs) = resolve_picoquic_libs_split(grandparent, dir) {
                return Some(PicoquicLibs {
                    search_dirs: vec![grandparent.to_path_buf(), dir.to_path_buf()],
                    libs,
                });
            }
        }
    }

    None
}

fn resolve_picoquic_libs_single_dir(dir: &Path) -> Option<Vec<&'static str>> {
    const REQUIRED: [(&str, &str); 5] = [
        ("picoquic_core", "picoquic-core"),
        ("picotls_core", "picotls-core"),
        ("picotls_fusion", "picotls-fusion"),
        ("picotls_minicrypto", "picotls-minicrypto"),
        ("picotls_openssl", "picotls-openssl"),
    ];
    let mut libs = Vec::with_capacity(REQUIRED.len());
    for (underscored, hyphenated) in REQUIRED {
        libs.push(find_lib_variant(dir, underscored, hyphenated)?);
    }
    Some(libs)
}

fn resolve_picoquic_libs_split(
    picoquic_dir: &Path,
    picotls_dir: &Path,
) -> Option<Vec<&'static str>> {
    let picoquic_core = find_lib_variant(picoquic_dir, "picoquic_core", "picoquic-core")?;
    let picotls_core = find_lib_variant(picotls_dir, "picotls_core", "picotls-core")?;
    let picotls_fusion = find_lib_variant(picotls_dir, "picotls_fusion", "picotls-fusion")?;
    let picotls_minicrypto =
        find_lib_variant(picotls_dir, "picotls_minicrypto", "picotls-minicrypto")?;
    let picotls_openssl = find_lib_variant(picotls_dir, "picotls_openssl", "picotls-openssl")?;
    Some(vec![
        picoquic_core,
        picotls_core,
        picotls_fusion,
        picotls_minicrypto,
        picotls_openssl,
    ])
}

fn find_lib_variant<'a>(dir: &Path, underscored: &'a str, hyphenated: &'a str) -> Option<&'a str> {
    let underscored_path = dir.join(format!("lib{}.a", underscored));
    if underscored_path.exists() {
        return Some(underscored);
    }
    let hyphen_path = dir.join(format!("lib{}.a", hyphenated));
    if hyphen_path.exists() {
        return Some(hyphenated);
    }
    None
}

fn create_archive(archive: &Path, objects: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = std::process::Command::new("ar");
    command.arg("crus").arg(archive);
    for obj in objects {
        command.arg(obj);
    }
    let status = command.status()?;
    if !status.success() {
        return Err("Failed to create static archive for slipstream objects.".into());
    }
    Ok(())
}

fn compile_cc(
    source: &Path,
    output: &Path,
    picoquic_include_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("cc")
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(output)
        .arg("-I")
        .arg(picoquic_include_dir)
        .status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}

fn compile_cc_with_includes(
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("cc");
    command.arg("-c").arg(source).arg("-o").arg(output);
    for dir in include_dirs {
        command.arg("-I").arg(dir);
    }
    let status = command.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}
