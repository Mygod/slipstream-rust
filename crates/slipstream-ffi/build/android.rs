use std::path::PathBuf;
use std::process::Command;

pub(crate) fn maybe_link_android_builtins(target: &str, cc: &str) {
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
