# TODO

## tc

- Add unit tests with real nlmon capture for the attributes above.

## link

- Support link kind `ovpn` (`IFLA_OVPN_MODE`) and `ppp`
  (`IFLA_PPP_DEV_FD`).
- Parse `IFLA_BRIDGE_MST`, `IFLA_BRIDGE_CFM` and `IFLA_BRIDGE_MRP`
  of `AfSpecBridge`.
- Convert `BridgeVlanXstats::flags` (`u16`) into a typed flags value,
  it holds `BRIDGE_VLAN_INFO_*` bits.
- Document `PrefixHeader::flags`: the kernel fills it from internal
  `IF_PREFIX_*` values, the UAPI defines no flag bits for it.

## unit tests

- Assert `InfoKind::Netdevsim` in the netdevsim test.
- Fix the `emit()` round trip of `test_parsing_link_vrf` or document
  why the emitted packet differs from the capture.
- Add `dpll_pin` tests when DPLL capable hardware is available.
