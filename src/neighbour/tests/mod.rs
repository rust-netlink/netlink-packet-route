// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
mod bridge;
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd;
#[cfg(test)]
mod ip;
