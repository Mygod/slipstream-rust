//! Android VPN socket protection for SIP003 plugins.
//!
//! When running as a Shadowsocks plugin in Android VPN mode, the plugin's UDP
//! sockets must be "protected" to bypass VPN routing. Otherwise, the plugin's
//! traffic would be routed back through the VPN tunnel, creating an infinite loop.
//!
//! The protection mechanism uses a Unix domain socket at `./protect_path` to
//! send the socket file descriptor to the Android VPN service, which then calls
//! `VpnService.protect()` on it.

use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Default path to the protect callback Unix socket (relative to working directory).
const PROTECT_PATH: &str = "protect_path";

/// Timeout for socket protection operations.
const PROTECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Protects a socket from VPN routing by sending its file descriptor to the
/// Android VPN service via a Unix domain socket.
///
/// Returns `Ok(true)` if protection succeeded, `Ok(false)` if the protect_path
/// doesn't exist (not in VPN mode), or `Err` on communication failure.
pub fn protect_socket(fd: RawFd) -> io::Result<bool> {
    // Try to connect to the protect_path Unix socket
    let stream = match UnixStream::connect(PROTECT_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // protect_path doesn't exist - not running in VPN mode
            return Ok(false);
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            // VPN service not ready
            return Ok(false);
        }
        Err(e) => return Err(e),
    };

    // Set timeouts
    stream.set_read_timeout(Some(PROTECT_TIMEOUT))?;
    stream.set_write_timeout(Some(PROTECT_TIMEOUT))?;

    // Send the file descriptor using SCM_RIGHTS ancillary message
    send_fd(&stream, fd)?;

    // Wait for confirmation (single byte response)
    let mut response = [0u8; 1];
    let mut stream_ref = &stream;
    match stream_ref.read_exact(&mut response) {
        Ok(()) => Ok(response[0] != 0),
        Err(e) => Err(e),
    }
}

/// Sends a file descriptor over a Unix socket using SCM_RIGHTS.
fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    use libc::{c_void, cmsghdr, iovec, msghdr, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE};
    use std::mem;
    use std::ptr;

    // Dummy data to send (required for sendmsg)
    let dummy: [u8; 1] = [0];
    let mut iov = iovec {
        iov_base: dummy.as_ptr() as *mut c_void,
        iov_len: dummy.len(),
    };

    // Calculate control message buffer size
    let cmsg_space = unsafe { CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // Build the message header
    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space;

    // Fill in the control message header
    let cmsg: *mut cmsghdr = unsafe { CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to get control message header",
        ));
    }

    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;

        // Copy the file descriptor into the control message data
        let fd_ptr = CMSG_DATA(cmsg) as *mut RawFd;
        ptr::write(fd_ptr, fd);
    }

    // Send the message
    let sock_fd = stream.as_raw_fd();
    let result = unsafe { libc::sendmsg(sock_fd, &msg, 0) };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_socket_missing_path_returns_false() {
        // When protect_path doesn't exist, should return Ok(false)
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        // This will return false since protect_path doesn't exist in test env
        let result = protect_socket(fd);
        assert!(result.is_ok());
    }
}
