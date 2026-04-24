use crate::cc::CcTool;

use std::path::PathBuf;

pub(crate) fn maybe_link_android_builtins(target: &str, cc: &CcTool) {
    let builtins = match android_builtins_name(target) {
        Some(name) => name,
        None => return,
    };
    let builtins_path = match clang_builtins_path(cc, builtins) {
        Some(path) => path,
        None => return,
    };
    let builtins_dir = match builtins_path.parent() {
        Some(dir) => dir,
        None => return,
    };
    println!("cargo:rustc-link-search=native={}", builtins_dir.display());
    println!("cargo:rustc-link-lib=static={}", builtins);
}

fn android_builtins_name(target: &str) -> Option<&'static str> {
    if target.starts_with("aarch64") {
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

fn clang_builtins_path(cc: &CcTool, builtins: &str) -> Option<PathBuf> {
    let output = cc.command().arg("-print-libgcc-file-name").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout);
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    if !path.exists() {
        return None;
    }
    let expected = format!("lib{}.a", builtins);
    if path.file_name()?.to_string_lossy() != expected {
        return None;
    }
    Some(path)
}
