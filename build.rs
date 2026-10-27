// SPDX-License-Identifier: MIT

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    cfg_alias(
        "has_message_family",
        cfg!(any(
            feature = "address",
            feature = "addrlabel",
            feature = "link",
            feature = "neighbour",
            feature = "neighbour-table",
            feature = "nsid",
            feature = "prefix",
            feature = "route",
            feature = "rule",
            feature = "stats",
            feature = "tc",
        )),
    );
    cfg_alias(
        "has_bitflags",
        cfg!(any(
            feature = "address",
            feature = "link",
            feature = "neighbour",
            feature = "route",
            feature = "rule",
            feature = "stats",
            feature = "tc",
        )),
    );
    cfg_alias(
        "has_ipv4_parser",
        cfg!(any(
            feature = "route",
            feature = "tc",
            feature = "link-info"
        )),
    );
    cfg_alias(
        "has_ipv6_parser",
        cfg!(any(
            feature = "route",
            feature = "tc",
            feature = "link-info",
            feature = "link-af-spec",
        )),
    );
}

fn cfg_alias(name: &str, enabled: bool) {
    // The single-colon syntax also works on our MSRV. Older Cargo versions
    // ignore rustc-check-cfg; newer versions use it to check every alias.
    println!("cargo:rustc-check-cfg=cfg({name})");
    if enabled {
        println!("cargo:rustc-cfg={name}");
    }
}
