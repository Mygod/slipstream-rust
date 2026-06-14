mod dns;
mod error;
mod pacing;
mod pinning;
mod platform;
mod runtime;
mod streams;

use jni::objects::{JBooleanArray, JIntArray, JObject, JObjectArray, JString};
use jni::sys::{jint, jstring, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};
use slipstream_core::{normalize_domain, parse_host_port_parts, AddressKind};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec, ResolverTransport};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::mpsc;

struct ClientHandle {
    stop_tx: mpsc::UnboundedSender<()>,
    thread: JoinHandle<()>,
}

static CLIENT: OnceLock<Mutex<Option<ClientHandle>>> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn client_slot() -> &'static Mutex<Option<ClientHandle>> {
    CLIENT.get_or_init(|| Mutex::new(None))
}

fn last_error_slot() -> &'static Mutex<Option<String>> {
    LAST_ERROR.get_or_init(|| Mutex::new(None))
}

fn set_last_error(message: impl Into<String>) {
    if let Ok(mut last_error) = last_error_slot().lock() {
        *last_error = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut last_error) = last_error_slot().lock() {
        *last_error = None;
    }
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    #[cfg(target_os = "android")]
    platform::set_java_vm(vm);
    #[cfg(not(target_os = "android"))]
    let _ = vm;
    JNI_VERSION_1_6
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStartSlipstreamClient(
    mut env: JNIEnv<'_>,
    _this: JObject<'_>,
    domain: JString<'_>,
    resolver_hosts: JObjectArray<'_>,
    resolver_ports: JIntArray<'_>,
    resolver_authoritative: JBooleanArray<'_>,
    listen_port: jint,
    listen_host: JString<'_>,
    congestion_control: JString<'_>,
    keep_alive_interval: jint,
    gso_enabled: bool,
    debug_poll: bool,
    debug_streams: bool,
    _idle_poll_interval: jint,
    _idle_timeout_ms: jint,
    resolver_transport: JString<'_>,
) -> jint {
    clear_last_error();
    if stop_running_client().is_err() {
        return -10;
    }

    let domain = match java_string(&mut env, &domain)
        .and_then(|value| normalize_domain(&value).map_err(|err| err.to_string()))
    {
        Ok(domain) => domain,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    let listen_host = match java_string(&mut env, &listen_host) {
        Ok(host) => host,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let congestion_control = match java_string(&mut env, &congestion_control) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let resolver_transport = match java_string(&mut env, &resolver_transport) {
        Ok(value) => parse_resolver_transport(&value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let mut resolvers = match read_resolvers(
        &mut env,
        resolver_hosts,
        resolver_ports,
        resolver_authoritative,
    ) {
        Ok(resolvers) => resolvers,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    if resolver_transport == ResolverTransport::Tcp && resolvers.len() > 1 {
        resolvers.truncate(1);
    }
    if resolvers.is_empty() || !(1..=u16::MAX as jint).contains(&listen_port) {
        set_last_error("invalid Slipstream resolver or listen port configuration");
        return -2;
    }

    let (stop_tx, stop_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (started_tx, started_rx) = std_mpsc::channel();
    let thread = match thread::Builder::new()
        .name("slipstream-client".to_string())
        .spawn(move || {
            RUNNING.store(true, Ordering::SeqCst);
            READY.store(false, Ordering::SeqCst);
            let _ = started_tx.send(());
            let runtime = match Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    set_last_error(format!("failed to build Tokio runtime: {}", err));
                    RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
            };
            let config = ClientConfig {
                tcp_listen_host: &listen_host,
                tcp_listen_port: listen_port as u16,
                resolvers: &resolvers,
                congestion_control: congestion_control.as_deref(),
                gso: gso_enabled,
                domain: &domain,
                cert: None,
                keep_alive_interval: keep_alive_interval.max(0) as usize,
                resolver_transport,
                debug_poll,
                debug_streams,
            };
            if let Err(err) = runtime.block_on(runtime::run_client_with_control(
                &config,
                Some(stop_rx),
                Some(ready_tx),
            )) {
                set_last_error(err.to_string());
            }
            READY.store(false, Ordering::SeqCst);
            RUNNING.store(false, Ordering::SeqCst);
        }) {
        Ok(thread) => thread,
        Err(err) => {
            set_last_error(format!("failed to spawn Slipstream client thread: {}", err));
            return -10;
        }
    };
    let _ = started_rx.recv_timeout(Duration::from_secs(1));
    thread::sleep(Duration::from_millis(150));
    if !RUNNING.load(Ordering::SeqCst) {
        let _ = thread.join();
        return -11;
    }

    thread::spawn(move || {
        while let Ok(ready) = ready_rx.recv() {
            READY.store(ready, Ordering::SeqCst);
        }
        READY.store(false, Ordering::SeqCst);
    });

    if let Ok(mut client) = client_slot().lock() {
        *client = Some(ClientHandle { stop_tx, thread });
        0
    } else {
        set_last_error("failed to lock Slipstream client state");
        -10
    }
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStopSlipstreamClient(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) {
    let _ = stop_running_client();
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsClientRunning(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> bool {
    RUNNING.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsQuicReady(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> bool {
    READY.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeGetLastError(
    env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> jstring {
    let message = last_error_slot()
        .lock()
        .ok()
        .and_then(|last_error| last_error.clone());
    match message {
        Some(message) => env
            .new_string(message)
            .map(|value| value.into_raw())
            .unwrap_or(ptr::null_mut()),
        None => ptr::null_mut(),
    }
}

fn stop_running_client() -> Result<(), String> {
    let handle = client_slot()
        .lock()
        .map_err(|_| "failed to lock Slipstream client state".to_string())?
        .take();
    if let Some(handle) = handle {
        let _ = handle.stop_tx.send(());
        let _ = handle.thread.join();
    }
    RUNNING.store(false, Ordering::SeqCst);
    READY.store(false, Ordering::SeqCst);
    Ok(())
}

fn java_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, String> {
    env.get_string(value)
        .map(|value| value.into())
        .map_err(|err| err.to_string())
}

fn parse_resolver_transport(value: &str) -> ResolverTransport {
    if value.trim().eq_ignore_ascii_case("tcp") {
        ResolverTransport::Tcp
    } else {
        ResolverTransport::Udp
    }
}

fn read_resolvers(
    env: &mut JNIEnv<'_>,
    resolver_hosts: JObjectArray<'_>,
    resolver_ports: JIntArray<'_>,
    resolver_authoritative: JBooleanArray<'_>,
) -> Result<Vec<ResolverSpec>, String> {
    let len = env
        .get_array_length(&resolver_hosts)
        .map_err(|err| err.to_string())?;
    if len == 0
        || env
            .get_array_length(&resolver_ports)
            .map_err(|err| err.to_string())?
            != len
        || env
            .get_array_length(&resolver_authoritative)
            .map_err(|err| err.to_string())?
            != len
    {
        return Err("resolver arrays must be non-empty and have the same length".to_string());
    }

    let mut ports = vec![0; len as usize];
    env.get_int_array_region(&resolver_ports, 0, &mut ports)
        .map_err(|err| err.to_string())?;
    let mut authoritative = vec![0u8; len as usize];
    env.get_boolean_array_region(&resolver_authoritative, 0, &mut authoritative)
        .map_err(|err| err.to_string())?;

    let mut resolvers = Vec::with_capacity(len as usize);
    for index in 0..len {
        let host_obj = env
            .get_object_array_element(&resolver_hosts, index)
            .map_err(|err| err.to_string())?;
        let host = java_string(env, &JString::from(host_obj))?;
        let port = ports[index as usize];
        if !(1..=u16::MAX as jint).contains(&port) {
            return Err(format!("invalid resolver port at index {}", index));
        }
        let resolver = parse_host_port_parts(&host, port as u16, AddressKind::Resolver)
            .map_err(|err| err.to_string())?;
        let mode = if authoritative[index as usize] != 0 {
            ResolverMode::Authoritative
        } else {
            ResolverMode::Recursive
        };
        resolvers.push(ResolverSpec { resolver, mode });
    }
    Ok(resolvers)
}
