// SPDX-License-Identifier: MIT

mod ffi;

use std::{
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

pub use ffi::*;

use super::freebsd;
pub struct NetlinkSocket(OwnedFd);

impl NetlinkSocket {
    pub fn new() -> Result<Self, std::io::Error> {
        unsafe {
            let fd = libc::socket(
                freebsd::AF_NETLINK as _,
                libc::SOCK_RAW,
                freebsd::NETLINK_ROUTE as _,
            );
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(NetlinkSocket(OwnedFd::from_raw_fd(fd)))
        }
    }
}

impl AsFd for NetlinkSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Read for NetlinkSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        unsafe {
            let ret = libc::read(
                self.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ret as usize)
        }
    }
}

impl Write for NetlinkSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        unsafe {
            let ret = libc::write(
                self.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
