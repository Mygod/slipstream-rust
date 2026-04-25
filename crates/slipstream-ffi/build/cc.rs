use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct CcTool {
    path: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

impl CcTool {
    fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    fn from_tool(tool: cc::Tool) -> Self {
        Self {
            path: tool.path().to_path_buf(),
            args: tool.args().to_vec(),
            env: tool.env().to_vec(),
        }
    }

    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(&self.path);
        command.args(&self.args);
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }
}

pub(crate) fn resolve_cc(target: &str) -> Result<CcTool, Box<dyn std::error::Error>> {
    if target.contains("android") {
        return Ok(CcTool::from_path(
            env::var("RUST_ANDROID_GRADLE_CC")
                .or_else(|_| env::var("CC"))
                .unwrap_or_else(|_| "cc".to_string()),
        ));
    }

    if let Ok(cc) = env::var("CC") {
        return Ok(CcTool::from_path(cc));
    }

    let mut builder = cc::Build::new();
    builder.target(target);
    let compiler = builder.get_compiler();

    Ok(CcTool::from_tool(compiler))
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
    if (target.contains("windows") || target.contains("pc-windows")) && target.contains("msvc") {
        return "lib.exe".to_string();
    }
    // For non-Windows targets, look for llvm-ar or ar in the compiler directory
    if let Some(dir) = cc.path().parent() {
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
    let is_windows = target.contains("windows") || target.contains("pc-windows");

    if is_windows {
        let mut lib_cmd = Command::new(ar);
        for (name, value) in cc.env() {
            lib_cmd.env(name, value);
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

    let mut cmd = cc.command();

    if is_windows {
        cmd.arg("/c")
            .arg(format!("/Fo:{}", output.display()))
            .arg(source)
            .arg("/D_WINDOWS");
        if target.contains("x86_64") {
            cmd.arg("/D_WINDOWS64");
        }
        cmd.arg(format!("/I{}", picoquic_include_dir.display()));
    } else {
        cmd.arg("-c").arg("-fPIC").arg("-o").arg(output).arg(source);
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

    let mut cmd = cc.command();

    if is_windows {
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
        cmd.arg("-c").arg("-fPIC").arg("-o").arg(output).arg(source);
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
