use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) enum CcTool {
    RawPath(PathBuf),
    Resolved(cc::Tool),
}

impl CcTool {
    pub(crate) fn command(&self) -> Command {
        match self {
            Self::RawPath(path) => Command::new(path),
            Self::Resolved(tool) => tool.to_command(),
        }
    }
}

pub(crate) fn resolve_cc(target: &str) -> Result<CcTool, Box<dyn std::error::Error>> {
    if target.contains("android") {
        return Ok(CcTool::RawPath(PathBuf::from(
            env::var("RUST_ANDROID_GRADLE_CC")
                .or_else(|_| env::var("CC"))
                .unwrap_or_else(|_| "cc".to_string()),
        )));
    }

    if let Ok(cc) = env::var("CC") {
        return Ok(CcTool::RawPath(PathBuf::from(cc)));
    }

    let mut builder = cc::Build::new();
    builder.target(target);
    let compiler = builder.try_get_compiler()?;

    Ok(CcTool::Resolved(compiler))
}

pub(crate) fn resolve_ar(target: &str, cc: &CcTool) -> String {
    if target.contains("android") {
        if let Ok(ar) = env::var("RUST_ANDROID_GRADLE_AR") {
            return ar;
        }
    }
    if let Ok(ar) = env::var("AR") {
        return ar;
    }
    if target.contains("msvc") {
        return "lib.exe".to_string();
    }
    // For non-Windows targets, look for llvm-ar or ar in the compiler directory
    let cc_path = match cc {
        CcTool::RawPath(path) => path.as_path(),
        CcTool::Resolved(tool) => tool.path(),
    };
    if let Some(dir) = cc_path.parent() {
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
    cc: &CcTool,
    archive: &Path,
    objects: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_msvc = target.contains("msvc");

    if is_msvc {
        let mut lib_cmd = Command::new(ar);
        if let CcTool::Resolved(tool) = cc {
            for (name, value) in tool.env() {
                lib_cmd.env(name, value);
            }
        }
        let mut out_arg = OsString::from("/OUT:");
        out_arg.push(archive.as_os_str());
        lib_cmd.arg(out_arg).arg("/NOLOGO");
        for obj in objects {
            lib_cmd.arg(obj);
        }
        let status = lib_cmd.status()?;
        if !status.success() {
            return Err("Failed to create static archive for slipstream objects.".into());
        }
    } else {
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
    cc: &CcTool,
    source: &Path,
    output: &Path,
    picoquic_include_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_windows = target.contains("windows") || target.contains("pc-windows");
    let is_msvc = target.contains("msvc");

    let mut cmd = cc.command();

    if is_msvc {
        cmd.arg("/c")
            .arg(format!("/Fo:{}", output.display()))
            .arg(source)
            .arg("/D_WINDOWS");
        if target.contains("x86_64") || target.contains("aarch64") {
            cmd.arg("/D_WINDOWS64");
        }
        cmd.arg(format!("/I{}", picoquic_include_dir.display()));
    } else {
        cmd.arg("-c").arg("-o").arg(output).arg(source);
        if !is_windows {
            cmd.arg("-fPIC");
        }
        if is_windows {
            cmd.arg("-D_WINDOWS");
            if target.contains("x86_64") || target.contains("aarch64") {
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
    cc: &CcTool,
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
) -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let is_windows = target.contains("windows") || target.contains("pc-windows");
    let is_msvc = target.contains("msvc");

    let mut cmd = cc.command();

    if is_msvc {
        cmd.arg("/c")
            .arg(format!("/Fo:{}", output.display()))
            .arg(source)
            .arg("/D_WINDOWS");
        if target.contains("x86_64") || target.contains("aarch64") {
            cmd.arg("/D_WINDOWS64");
        }
        for dir in include_dirs {
            cmd.arg(format!("/I{}", dir.display()));
        }
    } else {
        cmd.arg("-c").arg("-o").arg(output).arg(source);
        if !is_windows {
            cmd.arg("-fPIC");
        }
        if is_windows {
            cmd.arg("-D_WINDOWS");
            if target.contains("x86_64") || target.contains("aarch64") {
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
