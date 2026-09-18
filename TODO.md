# TODO

## tc

- Parse `TcAttribute::Rate` (`struct gnet_estimator`, 2 bytes) instead
  of keeping the payload as `Vec<u8>`. The kernel accepts it when a
  qdisc is created, but never dumps it.
- Parse `TcAttribute::Fcnt` as `u32`.
- Parse `TcAttribute::Stab` as nested attributes: `TCA_STAB_BASE`
  (`struct tc_sizespec`) plus `TCA_STAB_DATA` (u16 size table).
- Add `TCA_INGRESS_BLOCK` (13) and `TCA_EGRESS_BLOCK` (14), both are
  `u32` shared block indexes.
- Add `TCA_STATS_RATE_EST` (`struct gnet_stats_rate_est`) and
  `TCA_STATS_RATE_EST64` (`struct gnet_stats_rate_est64`) to
  `TcStats2`.
- Add unit tests with real nlmon capture for the attributes above.

## link

- Support link kind `ovpn` (`IFLA_OVPN_MODE`) and `ppp`
  (`IFLA_PPP_DEV_FD`).
- Parse `IFLA_HEADROOM` and `IFLA_TAILROOM` (both `u16`) and
  `IFLA_MAX_PACING_OFFLOAD_HORIZON`.
- Parse `IFLA_BRPORT_LEARNING_SYNC` of `InfoBridgePort`.
- Parse `IFLA_BRIDGE_MST`, `IFLA_BRIDGE_CFM` and `IFLA_BRIDGE_MRP`
  of `AfSpecBridge`.
- Convert `BridgeVlanXstats::flags` (`u16`) into a typed flags value,
  it holds `BRIDGE_VLAN_INFO_*` bits.
- Document `PrefixHeader::flags`: the kernel fills it from internal
  `IF_PREFIX_*` values, the UAPI defines no flag bits for it.
- Remove the stale `Use Vec<enum> for IFF_UP` comment in
  `src/link/af_spec/inet6.rs`, `Inet6IfaceFlags` is already typed.

## unit tests

- Add tests for `AddressAttribute::Broadcast` (IPv4), `Anycast` and
  `Multicast` (IPv6).
- Add tests for the `dsa`, `ifb`, `nlmon`, `tun`, `team` and
  `virt_wifi` link kinds, and assert `InfoKind::Netdevsim` in the
  netdevsim test.
- Replace the hand made payloads of the stats tests (`offload`,
  `bridge`, `bond` and `af_spec`) with real nlmon captures.
- Fix the `emit()` round trip of `test_parsing_link_vrf` or document
  why the emitted packet differs from the capture.
- Add `dpll_pin` tests when DPLL capable hardware is available.
