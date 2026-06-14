#![cfg(target_os = "android")]

use jni::objects::{JObject, JValue};
use jni::JavaVM;
use std::sync::OnceLock;
use tracing::warn;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

pub(crate) fn set_java_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
}

pub(crate) fn protect_socket_fd(fd: i32) -> bool {
    let Some(vm) = JAVA_VM.get() else {
        warn!("Android socket protection requested before JNI_OnLoad");
        return false;
    };
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(err) => {
            warn!(
                "Could not attach thread for Android socket protection: {}",
                err
            );
            return false;
        }
    };
    match env.call_static_method(
        "app/slipnet/tunnel/SlipstreamBridge",
        "protectSocket",
        "(I)Z",
        &[JValue::Int(fd)],
    ) {
        Ok(value) => value.z().unwrap_or(false),
        Err(err) => {
            warn!("Android socket protection failed for fd {}: {}", fd, err);
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            false
        }
    }
}
