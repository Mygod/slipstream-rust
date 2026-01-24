use std::io::{Error, ErrorKind};

pub fn is_transient_udp_error(err: &Error) -> bool {
    match err.kind() {
        ErrorKind::WouldBlock
        | ErrorKind::TimedOut
        | ErrorKind::Interrupted
        | ErrorKind::ConnectionReset => {
            return true;
        }
        _ => {}
    }

    #[cfg(not(windows))]
    {
        matches!(
            err.raw_os_error(),
            Some(code) if code == libc::ENETUNREACH || code == libc::EHOSTUNREACH
        )
    }
    #[cfg(windows)]
    {
        // Windows uses WinSock error codes: WSAENETUNREACH = 10051, WSAEHOSTUNREACH = 10065
        const WSAENETUNREACH: i32 = 10051;
        const WSAEHOSTUNREACH: i32 = 10065;
        matches!(
            err.raw_os_error(),
            Some(code) if code == WSAENETUNREACH || code == WSAEHOSTUNREACH
        )
    }
}
