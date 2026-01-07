// SPDX-License-Identifier: MIT

#[cfg(all(test, not(target_os = "freebsd")))]
mod bridge;
#[cfg(test)]
mod ip;
