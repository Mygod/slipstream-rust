use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn resolve_cc(target: &str) -> String {
    if target.contains("android") {
        return env::var("RUST_ANDROID_GRADLE_CC")
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string());
    }

    if let Ok(cc) = env::var("CC") {
        return cc;
    }

    if target.contains("windows") || target.contains("pc-windows") {
        let gcc_candidates = [
            "C:\\Strawberry\\c\\bin\\gcc.exe",
            "C:\\mingw64\\bin\\gcc.exe",
            "C:\\msys64\\mingw64\\bin\\gcc.exe",
        ];

        for candidate in &gcc_candidates {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
    }

    let builder = cc::Build::new();
    let compiler = builder.get_compiler();
    let path = compiler.path();
    let path_str = path.to_string_lossy().to_string();

    // Verify the compiler actually exists
    if !path.exists() {
        panic!("Compiler not found at: {}. Please install a C compiler (MinGW-w64, MSVC Build Tools, or Strawberry Perl).", path_str);
    }

    path_str
}

pub(crate) fn resolve_ar(target: &str, cc: &str) -> String {
    if target.contains("android") {
        if let Ok(ar) = env::var("RUST_ANDROID_GRADLE_AR") {
            return ar;
        }
    }
    if let Ok(ar) = env::var("AR") {
        return ar;
    }
    if target.contains("windows") || target.contains("pc-windows") {
        if cc.contains("gcc") || cc.contains("mingw") {
            if let Some(gcc_dir) = Path::new(cc).parent() {
                let ar_path = gcc_dir.join("ar.exe");
                if ar_path.exists() {
                    return ar_path.to_string_lossy().to_string();
                }
            }
            return "ar".to_string();
        }
        if target.contains("msvc") {
            return "lib.exe".to_string();
        }
    }
    // For non-Windows targets, look for llvm-ar or ar in the compiler directory
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

pub(crate) fn create_archive(
    ar: &str,
    archive: &Path,
    objects: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_windows = target.contains("windows") || target.contains("pc-windows");

    if is_windows && ar.contains("lib.exe") && ar != "ar" {
        // MSVC: use lib.exe
        let mut lib_cmd = Command::new("lib.exe");
        lib_cmd.arg("/OUT:").arg(archive).arg("/NOLOGO");
        for obj in objects {
            lib_cmd.arg(obj);
        }
        let status = lib_cmd.status()?;
        if !status.success() {
            return Err("Failed to create static archive for slipstream objects.".into());
        }
    } else {
        // GCC/Clang/MinGW: use ar
        let mut command = Command::new(ar);
        command.arg("crus").arg(archive);
        for obj in objects {
            command.arg(obj);
        }
        let status = command.status()?;
        if !status.success() {
            return Err("Failed to create static archive for slipstream objects.".into());
        }
    }
    Ok(())
}

pub(crate) fn compile_cc(
    cc: &str,
    source: &Path,
    output: &Path,
    picoquic_include_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_windows = target.contains("windows") || target.contains("pc-windows");
    let is_gcc = cc.contains("gcc") || cc.contains("mingw");

    let mut cmd = Command::new(cc);

    if is_windows && !is_gcc {
        // MSVC: cl.exe /c /Fo:output source.c /I include_dir /D_WINDOWS [/D_WINDOWS64]
        cmd.arg("/c")
            .arg(format!("/Fo:{}", output.display()))
            .arg(source)
            .arg("/D_WINDOWS");
        if target.contains("x86_64") {
            cmd.arg("/D_WINDOWS64");
        }
        cmd.arg(format!("/I{}", picoquic_include_dir.display()));
    } else {
        // GCC/Clang: cc -c -fPIC -o output source.c -I include_dir [-D_WINDOWS [-D_WINDOWS64]]
        cmd.arg("-c").arg("-fPIC").arg("-o").arg(output).arg(source);
        if is_windows {
            cmd.arg("-D_WINDOWS");
            if target.contains("x86_64") {
                cmd.arg("-D_WINDOWS64");
            }
        }
        cmd.arg("-I").arg(picoquic_include_dir);
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}

pub(crate) fn compile_cc_with_includes(
    cc: &str,
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_windows = target.contains("windows") || target.contains("pc-windows");
    let is_gcc = cc.contains("gcc") || cc.contains("mingw");

    let mut cmd = Command::new(cc);

    if is_windows && !is_gcc {
        // MSVC: cl.exe /c /Fo:output source.c /D_WINDOWS [/D_WINDOWS64] /I dir1 /I dir2
        cmd.arg("/c")
            .arg(format!("/Fo:{}", output.display()))
            .arg(source)
            .arg("/D_WINDOWS");
        if target.contains("x86_64") {
            cmd.arg("/D_WINDOWS64");
        }
        for dir in include_dirs {
            cmd.arg(format!("/I{}", dir.display()));
        }
    } else {
        // GCC/Clang: cc -c -fPIC -o output source.c [-D_WINDOWS [-D_WINDOWS64]] -I dir1 -I dir2
        cmd.arg("-c").arg("-fPIC").arg("-o").arg(output).arg(source);
        if is_windows {
            cmd.arg("-D_WINDOWS");
            if target.contains("x86_64") {
                cmd.arg("-D_WINDOWS64");
            }
        }
        for dir in include_dirs {
            cmd.arg("-I").arg(dir);
        }
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}
