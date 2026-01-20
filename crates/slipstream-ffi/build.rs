use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PICOQUIC_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_AUTO_BUILD");
    println!("cargo:rerun-if-env-changed=PICOQUIC_MINIMAL_BUILD");
    println!("cargo:rerun-if-env-changed=PICOTLS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_ROOT_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_CRYPTO_LIBRARY");
    println!("cargo:rerun-if-env-changed=OPENSSL_SSL_LIBRARY");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_ROOT");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");

    let openssl_paths = resolve_openssl_paths();
    let target = env::var("TARGET").unwrap_or_default();
    let auto_build = env_flag("PICOQUIC_AUTO_BUILD", true);
    let mut picoquic_include_dir = locate_picoquic_include_dir();
    let mut picoquic_lib_dir = locate_picoquic_lib_dir();
    let mut picotls_include_dir = locate_picotls_include_dir();

    if auto_build && (picoquic_include_dir.is_none() || picoquic_lib_dir.is_none()) {
        build_picoquic(&openssl_paths, &target)?;
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

    let cc = resolve_cc(&target);
    let ar = resolve_ar(&target, &cc);
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
    compile_cc(&cc, &cc_src, &cc_obj, &picoquic_include_dir)?;
    object_paths.push(cc_obj);

    let mixed_cc_obj = out_dir.join("slipstream_mixed_cc.c.o");
    compile_cc(&cc, &mixed_cc_src, &mixed_cc_obj, &picoquic_include_dir)?;
    object_paths.push(mixed_cc_obj);

    let poll_obj = out_dir.join("slipstream_poll.c.o");
    compile_cc(&cc, &poll_src, &poll_obj, &picoquic_include_dir)?;
    object_paths.push(poll_obj);

    let test_helpers_obj = out_dir.join("slipstream_test_helpers.c.o");
    compile_cc(
        &cc,
        &test_helpers_src,
        &test_helpers_obj,
        &picoquic_include_dir,
    )?;
    object_paths.push(test_helpers_obj);

    let picotls_layout_obj = out_dir.join("picotls_layout.c.o");
    compile_cc_with_includes(
        &cc,
        &picotls_layout_src,
        &picotls_layout_obj,
        &[&picoquic_include_dir, &picotls_include_dir],
    )?;
    object_paths.push(picotls_layout_obj);

    let archive = out_dir.join("libslipstream_client_objs.a");
    create_archive(&ar, &archive, &object_paths)?;
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

    if !target.contains("android") {
        println!("cargo:rustc-link-lib=dylib=pthread");
    } else {
        maybe_link_android_builtins(&target, &cc);
    }

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

struct OpenSslPaths {
    root: Option<PathBuf>,
    include: Option<PathBuf>,
    lib: Option<PathBuf>,
}

fn resolve_openssl_paths() -> OpenSslPaths {
    let root = env::var("OPENSSL_ROOT_DIR")
        .or_else(|_| env::var("OPENSSL_DIR"))
        .or_else(|_| env::var("DEP_OPENSSL_ROOT"))
        .ok()
        .map(PathBuf::from);
    let include = env::var("OPENSSL_INCLUDE_DIR")
        .or_else(|_| env::var("DEP_OPENSSL_INCLUDE"))
        .ok()
        .map(PathBuf::from);
    let lib = env::var("OPENSSL_LIB_DIR").ok().map(PathBuf::from);

    if root.is_some() || include.is_some() || lib.is_some() {
        let lib = lib.or_else(|| root.as_ref().and_then(|root| openssl_lib_dir(root)));
        let mut resolved = OpenSslPaths { root, include, lib };
        if cfg!(feature = "openssl-vendored") {
            if let (Some(target), Some(root)) = (env::var("TARGET").ok(), resolved.root.as_ref()) {
                let root_str = root.to_string_lossy();
                if !root_str.contains(&target) {
                    if let Some(target_paths) = resolve_openssl_from_build_output() {
                        resolved = target_paths;
                    }
                }
            }
        }
        return resolved;
    }

    if cfg!(feature = "openssl-vendored") {
        resolve_openssl_from_build_output().unwrap_or(OpenSslPaths {
            root: None,
            include: None,
            lib: None,
        })
    } else {
        OpenSslPaths {
            root: None,
            include: None,
            lib: None,
        }
    }
}

fn resolve_openssl_from_build_output() -> Option<OpenSslPaths> {
    let mut build_dirs = candidate_build_dirs();
    if let Some(dir) = locate_cargo_build_dir() {
        build_dirs.push(dir);
    }
    for build_dir in build_dirs {
        if let Some(paths) = find_openssl_sys_in_dir(&build_dir) {
            return Some(paths);
        }
    }
    None
}

fn candidate_build_dirs() -> Vec<PathBuf> {
    let target = env::var("TARGET").ok();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut roots = Vec::new();
    if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        roots.push(PathBuf::from(dir));
    }
    if let Some(root) = locate_repo_root() {
        roots.push(root.join("target"));
    }
    let mut build_dirs = Vec::new();
    for root in roots {
        if let Some(target) = &target {
            build_dirs.push(root.join(target).join(&profile).join("build"));
            build_dirs.push(root.join(target).join("build"));
        }
        build_dirs.push(root.join(&profile).join("build"));
        build_dirs.push(root.join("build"));
    }
    let mut deduped = Vec::new();
    for dir in build_dirs {
        if !deduped.contains(&dir) {
            deduped.push(dir);
        }
    }
    deduped
}

fn find_openssl_sys_in_dir(build_dir: &Path) -> Option<OpenSslPaths> {
    let mut best: Option<(SystemTime, OpenSslPaths)> = None;
    for entry in fs::read_dir(build_dir).ok()? {
        let path = entry.ok()?.path();
        let name = path.file_name()?.to_string_lossy();
        if !name.starts_with("openssl-sys-") {
            continue;
        }
        let output = path.join("output");
        let root_output = path.join("root-output");
        let candidate = parse_openssl_output(&output)
            .or_else(|| parse_openssl_output(&root_output))
            .or_else(|| openssl_paths_from_install(&path));
        let candidate = match candidate {
            Some(candidate) => candidate,
            None => continue,
        };
        let mtime = fs::metadata(&output)
            .and_then(|meta| meta.modified())
            .or_else(|_| fs::metadata(&root_output).and_then(|meta| meta.modified()))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if best.as_ref().map(|(time, _)| mtime > *time).unwrap_or(true) {
            best = Some((mtime, candidate));
        }
    }
    best.map(|(_, paths)| paths)
}

fn locate_cargo_build_dir() -> Option<PathBuf> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").ok()?);
    for ancestor in out_dir.ancestors() {
        if ancestor.file_name().and_then(|name| name.to_str()) == Some("build") {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn parse_openssl_output(path: &Path) -> Option<OpenSslPaths> {
    let contents = fs::read_to_string(path).ok()?;
    let mut root = None;
    let mut include = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("cargo:root=") {
            root = Some(PathBuf::from(value.trim()));
        } else if let Some(value) = line.strip_prefix("cargo:include=") {
            include = Some(PathBuf::from(value.trim()));
        }
    }
    let root = root?;
    let lib = openssl_lib_dir(&root);
    Some(OpenSslPaths {
        root: Some(root),
        include,
        lib,
    })
}

fn openssl_paths_from_install(build_dir: &Path) -> Option<OpenSslPaths> {
    let root = build_dir.join("out").join("openssl-build").join("install");
    let include = root.join("include");
    if !include.join("openssl").exists() {
        return None;
    }
    let lib = openssl_lib_dir(&root);
    Some(OpenSslPaths {
        root: Some(root),
        include: Some(include),
        lib,
    })
}

fn openssl_lib_dir(root: &Path) -> Option<PathBuf> {
    let candidate = root.join("lib");
    if candidate.exists() {
        return Some(candidate);
    }
    let candidate = root.join("lib64");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

fn build_picoquic(
    openssl_paths: &OpenSslPaths,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let mut command = Command::new(script);
    command
        .env("PICOQUIC_DIR", picoquic_dir)
        .env("PICOQUIC_BUILD_DIR", build_dir);
    if target.contains("android") {
        if let Ok(value) = env::var("ANDROID_NDK_HOME") {
            command.env("ANDROID_NDK_HOME", value);
        }
        if let Ok(value) = env::var("ANDROID_ABI") {
            command.env("ANDROID_ABI", value);
        }
        if let Ok(value) = env::var("ANDROID_PLATFORM") {
            command.env("ANDROID_PLATFORM", value);
        }
    }
    if cfg!(feature = "picoquic-minimal-build") {
        command.env("PICOQUIC_MINIMAL_BUILD", "1");
    }
    if let Some(root) = &openssl_paths.root {
        command.env("OPENSSL_ROOT_DIR", root);
        command.env("OPENSSL_DIR", root);
    }
    if cfg!(feature = "openssl-static") {
        command.env("OPENSSL_USE_STATIC_LIBS", "TRUE");
    }
    if let Some(include) = &openssl_paths.include {
        command.env("OPENSSL_INCLUDE_DIR", include);
    }
    if let Some(lib) = &openssl_paths.lib {
        command.env("OPENSSL_LIB_DIR", lib);
        if let Some(crypto) = resolve_openssl_library(lib, &["libcrypto.a", "libcrypto.so"]) {
            command.env("OPENSSL_CRYPTO_LIBRARY", crypto);
        }
        if let Some(ssl) = resolve_openssl_library(lib, &["libssl.a", "libssl.so"]) {
            command.env("OPENSSL_SSL_LIBRARY", ssl);
        }
    }
    let status = command.status()?;
    if !status.success() {
        return Err(
            "picoquic auto-build failed (run scripts/build_picoquic.sh for details)".into(),
        );
    }
    Ok(())
}

fn resolve_openssl_library(lib_dir: &Path, names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let candidate = lib_dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
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
    const REQUIRED: [(&str, &str); 4] = [
        ("picoquic_core", "picoquic-core"),
        ("picotls_core", "picotls-core"),
        ("picotls_openssl", "picotls-openssl"),
        ("picotls_minicrypto", "picotls-minicrypto"),
    ];
    let mut libs = Vec::with_capacity(REQUIRED.len() + 1);
    for (underscored, hyphenated) in REQUIRED {
        libs.push(find_lib_variant(dir, underscored, hyphenated)?);
    }
    if let Some(fusion) = find_lib_variant(dir, "picotls_fusion", "picotls-fusion") {
        libs.insert(3, fusion);
    }
    Some(libs)
}

fn resolve_picoquic_libs_split(
    picoquic_dir: &Path,
    picotls_dir: &Path,
) -> Option<Vec<&'static str>> {
    let picoquic_core = find_lib_variant(picoquic_dir, "picoquic_core", "picoquic-core")?;
    let picotls_core = find_lib_variant(picotls_dir, "picotls_core", "picotls-core")?;
    let picotls_minicrypto =
        find_lib_variant(picotls_dir, "picotls_minicrypto", "picotls-minicrypto")?;
    let picotls_openssl = find_lib_variant(picotls_dir, "picotls_openssl", "picotls-openssl")?;
    let mut libs = vec![picoquic_core, picotls_core, picotls_openssl];
    if let Some(fusion) = find_lib_variant(picotls_dir, "picotls_fusion", "picotls-fusion") {
        libs.push(fusion);
    }
    libs.push(picotls_minicrypto);
    Some(libs)
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

fn resolve_cc(target: &str) -> String {
    if target.contains("android") {
        env::var("RUST_ANDROID_GRADLE_CC")
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string())
    } else {
        env::var("CC").unwrap_or_else(|_| "cc".to_string())
    }
}

fn resolve_ar(target: &str, cc: &str) -> String {
    if target.contains("android") {
        if let Ok(ar) = env::var("RUST_ANDROID_GRADLE_AR") {
            return ar;
        }
    }
    if let Ok(ar) = env::var("AR") {
        return ar;
    }
    if let Some(dir) = Path::new(cc).parent() {
        let candidate = dir.join("llvm-ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        let candidate = dir.join("ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "ar".to_string()
}

fn create_archive(
    ar: &str,
    archive: &Path,
    objects: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = std::process::Command::new(ar);
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
    cc: &str,
    source: &Path,
    output: &Path,
    picoquic_include_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(cc)
        .arg("-c")
        .arg("-fPIC")
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
    cc: &str,
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(cc);
    command
        .arg("-c")
        .arg("-fPIC")
        .arg(source)
        .arg("-o")
        .arg(output);
    for dir in include_dirs {
        command.arg("-I").arg(dir);
    }
    let status = command.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}

fn maybe_link_android_builtins(target: &str, cc: &str) {
    let builtins = match android_builtins_name(target) {
        Some(name) => name,
        None => return,
    };
    let resource_dir = match clang_resource_dir(cc) {
        Some(dir) => dir,
        None => return,
    };
    let builtins_dir = resource_dir.join("lib").join("linux");
    let builtins_path = builtins_dir.join(format!("lib{}.a", builtins));
    if !builtins_path.exists() {
        return;
    }
    println!("cargo:rustc-link-search=native={}", builtins_dir.display());
    println!("cargo:rustc-link-lib=static={}", builtins);
}

fn android_builtins_name(target: &str) -> Option<&'static str> {
    if target.contains("aarch64") {
        Some("clang_rt.builtins-aarch64-android")
    } else if target.starts_with("arm") {
        Some("clang_rt.builtins-arm-android")
    } else if target.starts_with("i686") {
        Some("clang_rt.builtins-i686-android")
    } else if target.starts_with("x86_64") {
        Some("clang_rt.builtins-x86_64-android")
    } else {
        None
    }
}

fn clang_resource_dir(cc: &str) -> Option<PathBuf> {
    let output = Command::new(cc).arg("-print-resource-dir").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&output.stdout);
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir))
}
