// SPDX-License-Identifier: MIT

#[cfg(all(test, not(target_os = "freebsd")))]
mod bridge;
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd;
#[cfg(test)]
mod ip;
