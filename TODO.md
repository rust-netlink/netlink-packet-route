# TODO

## tc

## link

- Parse `IFLA_BRIDGE_MST`, `IFLA_BRIDGE_CFM` and `IFLA_BRIDGE_MRP`
  of `AfSpecBridge`.
- Convert `BridgeVlanXstats::flags` (`u16`) into a typed flags value,
  it holds `BRIDGE_VLAN_INFO_*` bits.
- Document `PrefixHeader::flags`: the kernel fills it from internal
  `IF_PREFIX_*` values, the UAPI defines no flag bits for it.

## unit tests

- Assert `InfoKind::Netdevsim` in the netdevsim test.
- Add `dpll_pin` tests when DPLL capable hardware is available.
