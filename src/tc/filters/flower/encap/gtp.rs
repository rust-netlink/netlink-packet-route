use anyhow::Context;
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::parsers::parse_u8;
use netlink_packet_utils::{DecodeError, Parseable};

/// I don't have any real experience with GTP.
/// It looks like the [spec for GTP `PduType`][1] is available
/// but the number of codes is fairly large, and I am not sure
/// more than `u8` is justified.
/// I can implement all of those codes in an enum if needed.
///
/// [1]: https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf#page=22

const TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE: u16 = 1; /* u8 */
const TCA_FLOWER_KEY_ENC_OPT_GTP_QFI: u16 = 2; /* u8 */

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    PduType(u8),
    Qfi(u8),
    Other(DefaultNla),
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        match self {
            Options::PduType(_) => TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE,
            Options::Qfi(_) => TCA_FLOWER_KEY_ENC_OPT_GTP_QFI,
            Options::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Options::PduType(pdu_type) => {
                buffer[0] = *pdu_type;
            }
            Options::Qfi(qfi) => {
                buffer[0] = *qfi;
            }
            Options::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE => {
                Options::PduType(parse_u8(payload)?)
            }
            TCA_FLOWER_KEY_ENC_OPT_GTP_QFI => {
                Options::Qfi(parse_u8(payload)?)
            }
            _ => Options::Other(
                DefaultNla::parse(buf).context("failed to parse gtp nla")?,
            ),
        })
    }
}
