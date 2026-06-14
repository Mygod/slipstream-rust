#![cfg(target_os = "android")]

use jni::objects::JValue;
use jni::JavaVM;
use std::sync::OnceLock;
use tracing::warn;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

pub(crate) fn set_java_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
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
