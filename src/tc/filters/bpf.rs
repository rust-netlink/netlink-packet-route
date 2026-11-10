// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_string, parse_u32, DecodeError, DefaultNla,
    EncodeError, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::tc::{TcHandle, TcU32OptionFlags};

const TCA_BPF_CLASSID: u16 = 3;
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAGS_GEN: u16 = 9;
const TCA_BPF_TAG: u16 = 10;
const TCA_BPF_ID: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcFilterBpf {}

impl TcFilterBpf {
    pub const KIND: &'static str = "bpf";

    // Defined in https://elixir.bootlin.com/linux/v6.12/source/include/uapi/linux/bpf.h#L6550
    pub const BPF_TAG_SIZE: usize = 8;
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterBpfOption {
    ClassId(TcHandle),
    ProgFd(u32),
    ProgName(String),
    Flags(TcBpfFlags),
    FlagsGeneric(TcU32OptionFlags),
    ProgTag([u8; TcFilterBpf::BPF_TAG_SIZE]),
    ProgId(u32),
    Other(DefaultNla),
}

impl Nla for TcFilterBpfOption {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::ClassId(i) => append_u32(out, (*i).into()),
            Self::ProgFd(fd) => append_u32(out, *fd),
            Self::ProgName(name) => {
                append_bytes(out, name.as_bytes());
                out.push(0);
            }
            Self::Flags(flags) => append_u32(out, flags.bits()),
            Self::FlagsGeneric(flags_gen) => append_u32(out, flags_gen.bits()),
            Self::ProgTag(tag) => append_bytes(out, tag),
            Self::ProgId(id) => append_u32(out, *id),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ClassId(_) => TCA_BPF_CLASSID,
            Self::ProgFd(_) => TCA_BPF_FD,
            Self::ProgName(_) => TCA_BPF_NAME,
            Self::Flags(_) => TCA_BPF_FLAGS,
            Self::FlagsGeneric(_) => TCA_BPF_FLAGS_GEN,
            Self::ProgTag(_) => TCA_BPF_TAG,
            Self::ProgId(_) => TCA_BPF_ID,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcFilterBpfOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_BPF_CLASSID => Self::ClassId(
                parse_u32(payload)
                    .context("failed to parse TCA_BPF_CLASSID")?
                    .into(),
            ),
            TCA_BPF_FD => Self::ProgFd(
                parse_u32(payload).context("failed to parse TCA_BPF_FD")?,
            ),
            TCA_BPF_NAME => Self::ProgName(
                parse_string(payload)
                    .context("failed to parse TCA_BPF_NAME")?,
            ),
            TCA_BPF_FLAGS => Self::Flags(TcBpfFlags::from_bits_retain(
                parse_u32(payload).context("failed to parse TCA_BPF_FLAGS")?,
            )),
            TCA_BPF_FLAGS_GEN => {
                Self::FlagsGeneric(TcU32OptionFlags::from_bits_retain(
                    parse_u32(payload)
                        .context("failed to parse TCA_BPF_FLAGS_GEN")?,
                ))
            }
            TCA_BPF_TAG => {
                let tag: [u8; TcFilterBpf::BPF_TAG_SIZE] =
                    payload.try_into().map_err(|_| {
                        DecodeError::nla_length_mismatch(
                            TcFilterBpf::BPF_TAG_SIZE,
                            payload.len(),
                        )
                    })?;
                Self::ProgTag(tag)
            }
            TCA_BPF_ID => Self::ProgId(
                parse_u32(payload).context("failed to parse TCA_BPF_ID")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse bpf nla")?,
            ),
        })
    }
}

const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1 << 0;

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct TcBpfFlags: u32 {
        const DirectAction = TCA_BPF_FLAG_ACT_DIRECT;
        const _ = !0;
    }
}
