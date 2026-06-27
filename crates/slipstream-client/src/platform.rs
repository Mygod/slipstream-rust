#![cfg(target_os = "android")]

use jni::objects::JValue;
use jni::JavaVM;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{warn, Level};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static LOG_FILE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
const MAX_NATIVE_LOG_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn set_java_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
}

pub(crate) fn init_android_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "info,slipstream::dns::debug=debug,slipstream::streams::command_dispatch=debug,hyper=info,mio=info,tokio=info,rustls=info,openssl=info",
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(AndroidLogWriterFactory)
        .with_ansi(false)
        .with_target(true)
        .without_time()
        .try_init();
}

pub(crate) fn set_log_file_path(path: Option<String>) {
    let slot = LOG_FILE.get_or_init(|| Mutex::new(None));
    if let Ok(mut value) = slot.lock() {
        *value = path
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from);
    }
}

pub(crate) fn protect_socket_fd(fd: i32) -> bool {
    let Some(vm) = JAVA_VM.get() else {
        warn!(
            "Android socket protection requested before JNI_OnLoad; continuing because SlipNet excludes itself from the VPN"
        );
        return true;
    };
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(err) => {
            warn!(
                "Could not attach thread for Android socket protection: {}; continuing because SlipNet excludes itself from the VPN",
                err
            );
            return true;
        }
    };
    match env.call_static_method(
        "app/slipnet/tunnel/SlipstreamBridge",
        "protectSocket",
        "(I)Z",
        &[JValue::Int(fd)],
    ) {
        Ok(value) => match value.z() {
            Ok(true) => true,
            Ok(false) => {
                warn!(
                    "Android VpnService.protect({}) returned false; continuing because SlipNet excludes itself from the VPN",
                    fd
                );
                true
            }
            Err(err) => {
                warn!(
                    "Android socket protection returned a non-boolean result for fd {}: {}; continuing because SlipNet excludes itself from the VPN",
                    fd, err
                );
                true
            }
        },
        Err(err) => {
            warn!(
                "Android socket protection failed for fd {}: {}; continuing because SlipNet excludes itself from the VPN",
                fd, err
            );
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            true
        }
    }
}

#[derive(Clone, Copy)]
struct AndroidLogWriterFactory;

impl<'a> MakeWriter<'a> for AndroidLogWriterFactory {
    type Writer = AndroidLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        AndroidLogWriter {
            priority: 3,
            buffer: Vec::with_capacity(512),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        AndroidLogWriter {
            priority: android_priority(meta.level()),
            buffer: Vec::with_capacity(512),
        }
    }
}

struct AndroidLogWriter {
    priority: i32,
    buffer: Vec<u8>,
}

impl Write for AndroidLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit();
        Ok(())
    }
}

impl Drop for AndroidLogWriter {
    fn drop(&mut self) {
        self.emit();
    }
}

impl AndroidLogWriter {
    fn emit(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let message = String::from_utf8_lossy(&self.buffer).trim().to_string();
        self.buffer.clear();
        if !message.is_empty() {
            write_native_log(self.priority, &message);
        }
    }
}

fn android_priority(level: &Level) -> i32 {
    match *level {
        Level::ERROR => 6,
        Level::WARN => 5,
        Level::INFO => 4,
        Level::DEBUG => 3,
        Level::TRACE => 2,
    }
}

fn write_native_log(priority: i32, message: &str) {
    let level = match priority {
        6 => "E",
        5 => "W",
        4 => "I",
        3 => "D",
        _ => "V",
    };
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    let line = format!("{} {} SlipstreamNative: {}\n", ts_ms, level, message);
    let path = LOG_FILE
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|value| value.clone()));
    if let Some(path) = path {
        if path
            .metadata()
            .map(|metadata| metadata.len() > MAX_NATIVE_LOG_BYTES)
            .unwrap_or(false)
        {
            let _ = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .and_then(|mut file| file.write_all(b"native log rotated\n"));
        }
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
    }
}
