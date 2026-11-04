// SPDX-License-Identifier: MIT

use std::net::Ipv6Addr;

use netlink_packet_core::{
    append_bytes, append_u32, append_u32_be, parse_u32, parse_u32_be,
    DecodeError, DefaultNla, EncodeError, EncodeErrorKind, ErrorContext, Nla,
    NlaBuffer, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::ip::parse_ipv6_addr;

const SEG6_IPTUN_MODE_INLINE: u32 = 0;
const SEG6_IPTUN_MODE_ENCAP: u32 = 1;
//const SEG6_IPTUN_MODE_L2ENCAP: u32 = 2;
//const SEG6_IPTUN_MODE_ENCAP_RED: u32 = 3;
//const SEG6_IPTUN_MODE_L2ENCAP_RED: u32 = 4;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Seg6Mode {
    // Inline mode for Seg6
    #[default]
    Inline,
    // Encapsulation mode for Seg6
    Encap,
    // L2ENCAP = 2,
    // ENCAP_RED = 3,
    // L2ENCAP_RED = 4
    Other(u32),
}

impl From<Seg6Mode> for u32 {
    fn from(value: Seg6Mode) -> Self {
        match value {
            Seg6Mode::Inline => SEG6_IPTUN_MODE_INLINE,
            Seg6Mode::Encap => SEG6_IPTUN_MODE_ENCAP,
            Seg6Mode::Other(i) => i,
        }
    }
}

impl From<u32> for Seg6Mode {
    fn from(value: u32) -> Self {
        match value {
            SEG6_IPTUN_MODE_INLINE => Seg6Mode::Inline,
            SEG6_IPTUN_MODE_ENCAP => Seg6Mode::Encap,
            v => Seg6Mode::Other(v),
        }
    }
}

const SEG6_IPTUNNEL_SRH: u16 = 1;
// `tunsrc` of the `encap seg6` command.
const SEG6_IPTUNNEL_SRC: u16 = 2;
// `lookup` of the `encap seg6` command. This attribute is defined in the copy
// of the uapi header shipped by `iproute2`, the kernel ignores it, therefore
// it is not part of the netlink dump of a seg6 route.
const SEG6_IPTUNNEL_TABLE: u16 = 3;

// `SR6_FLAG1_HMAC` and `SR6_TLV_HMAC` of `include/uapi/linux/seg6.h`.
const SR6_FLAG1_HMAC: u8 = 1 << 3;
const SR6_TLV_HMAC: u8 = 5;
// `struct sr6_tlv_hmac`: the 2 octet TLV header, 2 reserved octets, the
// 4 octet HMAC key ID and the 32 octet HMAC field.
const SR6_HMAC_TLV_LEN: usize = 40;

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteSeg6IpTunnel {
    // Use an IPv6 segment routing header
    Seg6(Seg6Header),
    // The `tunsrc` of an encapsulation mode tunnel: the source address of the
    // outer IPv6 header
    Src(Ipv6Addr),
    // The `lookup` of an encapsulation mode tunnel: the routing table used
    // for the lookup of the destination address of the outer IPv6 header
    Table(u32),
    Other(DefaultNla),
}

impl Nla for RouteSeg6IpTunnel {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            RouteSeg6IpTunnel::Seg6(v) => v.emit_value(out)?,
            RouteSeg6IpTunnel::Src(addr) => append_bytes(out, &addr.octets()),
            RouteSeg6IpTunnel::Table(table) => append_u32(out, *table),
            RouteSeg6IpTunnel::Other(v) => append_bytes(out, v.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            RouteSeg6IpTunnel::Seg6(v) => v.kind(),
            RouteSeg6IpTunnel::Src(_) => SEG6_IPTUNNEL_SRC,
            RouteSeg6IpTunnel::Table(_) => SEG6_IPTUNNEL_TABLE,
            RouteSeg6IpTunnel::Other(v) => v.kind(),
        }
    }
}

const SEG6_IPTUN_MODE_LEN: usize = 4;
const SEG6_SRH_FIXED_LEN: usize = 8;
const SEG6_HEADER_LEN: usize = SEG6_IPTUN_MODE_LEN + SEG6_SRH_FIXED_LEN;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct Seg6MessageBuffer {
    mode: u32,
    nexthdr: u8,
    hdrlen: u8,
    seg_type: u8,
    segments_left: u8,
    first_segment: u8,
    flags: u8,
    tag: u16,
}

const SEG6_SEGMENT_LEN: usize = 16;

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct Seg6Header {
    // Operation mode
    pub mode: Seg6Mode,
    // List of segments
    pub segments: Vec<Ipv6Addr>,
    // The key ID of the `SR6_TLV_HMAC` TLV appended to the segment routing
    // header, `None` when the header has no HMAC TLV. This matches the `hmac`
    // argument of the `iproute2` `encap seg6` command.
    pub hmac: Option<u32>,
}

impl Seg6Header {
    fn get_segments(
        buf: &[u8],
        segments: &mut Vec<Ipv6Addr>,
    ) -> Result<(), DecodeError> {
        // are there any remaining segments ?
        if buf.len() >= SEG6_SEGMENT_LEN {
            let segment = parse_ipv6_addr(&buf[..SEG6_SEGMENT_LEN])?;
            segments.push(segment);
            Self::get_segments(&buf[SEG6_SEGMENT_LEN..], segments)?;
        }
        Ok(())
    }
}

impl Nla for Seg6Header {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // Some sources for understanding the format of Seg6 in Netlink
        //
        // torvalds/linux:
        //      include/uapi/linux/seg6.h
        //      include/uapi/linux/seg6_iptunnel.h
        //
        // iproute2/iproute2
        //      ip/iproute_lwtunnel.c parse_encap_seg6()

        let number_segments = self.segments.len();

        if number_segments == 0 {
            return Err(EncodeError::new(
                EncodeErrorKind::InvalidValue,
                "SEG6 header requires at least one segment",
            ));
        }

        let srhlen = SEG6_SRH_FIXED_LEN
            + SEG6_SEGMENT_LEN * number_segments
            + if self.hmac.is_some() {
                SR6_HMAC_TLV_LEN
            } else {
                0
            };

        let raw = Seg6MessageBuffer {
            mode: self.mode.into(),
            nexthdr: 0,
            hdrlen: ((srhlen >> 3) - 1) as u8,
            seg_type: 4,
            segments_left: (number_segments - 1) as u8,
            first_segment: (number_segments - 1) as u8,
            flags: if self.hmac.is_some() {
                SR6_FLAG1_HMAC
            } else {
                0
            },
            tag: 0,
        };
        append_bytes(out, raw.as_bytes());

        for segment in self.segments.iter().rev() {
            append_bytes(out, &segment.octets());
        }

        if let Some(key_id) = self.hmac {
            out.push(SR6_TLV_HMAC);
            out.push((SR6_HMAC_TLV_LEN - 2) as u8);
            // The 2 reserved octets and the 32 octet HMAC field are zero.
            append_bytes(out, &[0, 0]);
            append_u32_be(out, key_id);
            append_bytes(out, &[0u8; 32]);
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        SEG6_IPTUNNEL_SRH
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for RouteSeg6IpTunnel
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_core::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_IPTUNNEL_SRH => {
                let (raw, _) = Seg6MessageBuffer::ref_from_prefix(payload)
                    .map_err(|_| {
                        DecodeError::buffer_too_small(
                            payload.len(),
                            SEG6_HEADER_LEN,
                        )
                    })?;

                // The `hdrlen` field of the SRH covers the segment list and
                // the optional trailing HMAC TLV.
                let srh_len = (usize::from(raw.hdrlen) + 1) << 3;
                if srh_len < SEG6_SRH_FIXED_LEN
                    || payload.len() < SEG6_IPTUN_MODE_LEN + srh_len
                {
                    return Err(DecodeError::from(format!(
                        "Invalid SEG6_IPTUNNEL_SRH value {payload:?}"
                    )));
                }
                let srh = &payload
                    [SEG6_IPTUN_MODE_LEN..SEG6_IPTUN_MODE_LEN + srh_len];

                let hmac = if raw.flags & SR6_FLAG1_HMAC != 0 {
                    if srh_len < SEG6_SRH_FIXED_LEN + SR6_HMAC_TLV_LEN {
                        return Err(DecodeError::from(format!(
                            "Invalid SEG6_IPTUNNEL_SRH HMAC TLV {payload:?}"
                        )));
                    }
                    let tlv = &srh[srh_len - SR6_HMAC_TLV_LEN..];
                    Some(
                        parse_u32_be(&tlv[4..8])
                            .context("Invalid SR6_TLV_HMAC key ID")?,
                    )
                } else {
                    None
                };

                let segments_len = srh_len
                    - SEG6_SRH_FIXED_LEN
                    - if hmac.is_some() { SR6_HMAC_TLV_LEN } else { 0 };
                if segments_len % SEG6_SEGMENT_LEN != 0 {
                    return Err(DecodeError::from(format!(
                        "Invalid SEG6_IPTUNNEL_SRH segment list {payload:?}"
                    )));
                }

                let mut segments: Vec<Ipv6Addr> = vec![];
                Seg6Header::get_segments(
                    &srh[SEG6_SRH_FIXED_LEN..SEG6_SRH_FIXED_LEN + segments_len],
                    &mut segments,
                )?;

                let segments: Vec<Ipv6Addr> =
                    segments.into_iter().rev().collect();

                RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::from(raw.mode),
                    segments,
                    hmac,
                })
            }
            SEG6_IPTUNNEL_SRC => Self::Src(
                parse_ipv6_addr(payload)
                    .context("invalid SEG6_IPTUNNEL_SRC value")?,
            ),
            SEG6_IPTUNNEL_TABLE => Self::Table(
                parse_u32(payload)
                    .context("invalid SEG6_IPTUNNEL_TABLE value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}
