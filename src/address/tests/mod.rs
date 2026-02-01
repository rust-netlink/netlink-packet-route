// SPDX-License-Identifier: MIT

#[cfg(all(test, target_os = "freebsd"))]
mod freebsd;
#[cfg(test)]
mod ipv4;
#[cfg(test)]
mod ipv6;
