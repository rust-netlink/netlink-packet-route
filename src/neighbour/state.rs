// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;

const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

const NUD_KNOWN: u16 = NUD_INCOMPLETE
    | NUD_REACHABLE
    | NUD_STALE
    | NUD_DELAY
    | NUD_PROBE
    | NUD_FAILED
    | NUD_NOARP
    | NUD_PERMANENT;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[non_exhaustive]
    pub struct NeighbourState: u16 {
        const Incomplete = NUD_INCOMPLETE;
        const Reachable = NUD_REACHABLE;
        const Stale = NUD_STALE;
        const Delay = NUD_DELAY;
        const Probe = NUD_PROBE;
        const Failed = NUD_FAILED;
        const Noarp = NUD_NOARP;
        const Permanent = NUD_PERMANENT;
        const _ = !0;
    }
}

impl NeighbourState {
    /// The state of a neighbour entry with no `NUD_*` bits set.
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self::empty();
}

impl From<NeighbourState> for u16 {
    fn from(v: NeighbourState) -> u16 {
        v.bits()
    }
}

impl From<u16> for NeighbourState {
    fn from(d: u16) -> Self {
        Self::from_bits_retain(d)
    }
}

impl std::fmt::Display for NeighbourState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for (flag, name) in [
            (Self::Incomplete, "incomplete"),
            (Self::Reachable, "reachable"),
            (Self::Stale, "stale"),
            (Self::Delay, "delay"),
            (Self::Probe, "probe"),
            (Self::Failed, "failed"),
            (Self::Noarp, "noarp"),
            (Self::Permanent, "permanent"),
        ] {
            if !self.contains(flag) {
                continue;
            }
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(name)?;
            first = false;
        }

        let unknown = self.bits() & !NUD_KNOWN;
        if unknown != 0 {
            if !first {
                f.write_str(" ")?;
            }
            write!(f, "other(0x{unknown:x})")?;
            first = false;
        }

        if first {
            f.write_str("none")?;
        }

        Ok(())
    }
}

impl std::str::FromStr for NeighbourState {
    type Err = DecodeError;

    fn from_str(state: &str) -> Result<Self, Self::Err> {
        let mut parsed = Self::empty();
        let mut found = false;

        for token in state.split_whitespace() {
            let flag = match token {
                "incomplete" => Self::Incomplete,
                "reachable" => Self::Reachable,
                "stale" => Self::Stale,
                "delay" => Self::Delay,
                "probe" => Self::Probe,
                "failed" => Self::Failed,
                "noarp" => Self::Noarp,
                "permanent" => Self::Permanent,
                "none" => Self::None,
                _ => {
                    return Err(format!("Invalid state string '{state}'").into())
                }
            };
            parsed |= flag;
            found = true;
        }

        if !found {
            return Err(format!("Invalid state string '{state}'").into());
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::NeighbourState;

    #[test]
    fn test_neighbour_state_decoding() {
        assert!(matches!(
            NeighbourState::from_str("incomplete"),
            Ok(NeighbourState::Incomplete)
        ));
        assert!(matches!(
            NeighbourState::from_str("reachable"),
            Ok(NeighbourState::Reachable)
        ));
        assert!(matches!(
            NeighbourState::from_str("stale"),
            Ok(NeighbourState::Stale)
        ));
        assert!(matches!(
            NeighbourState::from_str("delay"),
            Ok(NeighbourState::Delay)
        ));
        assert!(matches!(
            NeighbourState::from_str("probe"),
            Ok(NeighbourState::Probe)
        ));
        assert!(matches!(
            NeighbourState::from_str("failed"),
            Ok(NeighbourState::Failed)
        ));
        assert!(matches!(
            NeighbourState::from_str("noarp"),
            Ok(NeighbourState::Noarp)
        ));
        assert!(matches!(
            NeighbourState::from_str("permanent"),
            Ok(NeighbourState::Permanent)
        ));
        assert!(matches!(
            NeighbourState::from_str("none"),
            Ok(NeighbourState::None)
        ));
        assert!(matches!(NeighbourState::from_str("None"), Err(..)));
        assert!(matches!(NeighbourState::from_str("not a nud"), Err(..)));
    }

    #[test]
    fn test_neighbour_state_multiple_flags() {
        assert_eq!(
            NeighbourState::from_str("reachable permanent").unwrap(),
            NeighbourState::Reachable | NeighbourState::Permanent
        );
        assert_eq!(
            NeighbourState::from(
                NeighbourState::Noarp.bits() | NeighbourState::Permanent.bits()
            ),
            NeighbourState::Noarp | NeighbourState::Permanent
        );
    }

    #[test]
    fn test_neighbour_state_display() {
        assert_eq!(
            (NeighbourState::Reachable | NeighbourState::Permanent).to_string(),
            "reachable permanent"
        );
        assert_eq!(NeighbourState::None.to_string(), "none");
        assert_eq!(
            NeighbourState::from_bits_retain(0x100).to_string(),
            "other(0x100)"
        );
    }
}
