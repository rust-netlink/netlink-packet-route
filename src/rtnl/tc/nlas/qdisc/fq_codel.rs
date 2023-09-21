// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    traits::Emitable,
    DecodeError,
};

use crate::nlas::tc::{NLA_HEADER_LEN, ATTR_LEN};

pub const FQ_CODEL: &str = "fq_codel";
pub const FQ_CODEL_LEN: usize = 36;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct FqCodel {
    pub target: u32,
    pub limit: u32,
    pub interval: u32,
    pub ecn: u32,
    pub flows: u32,
    pub quantum: u32,
    pub ce_threshold: u32,
    pub drop_batch_size: u32,
    pub memory_limit: u32,
}

buffer!(FqCodelBuffer(FQ_CODEL_LEN) {
    target: (u32, 0..4),
    limit: (u32, 4..8),
    interval: (u32, 8..12),
    ecn: (u32, 12..16),
    flows: (u32, 16..20),
    quantum: (u32, 20..24),
    ce_threshold: (u32, 24..28),
    drop_batch_size: (u32, 28..32),
    memory_limit: (u32, 32..36),
});

impl FqCodel {
    pub fn new(data: &[u8]) -> Result<Self, DecodeError> {
        unmarshal_fq_codel(data)
    }
}

impl Emitable for FqCodel {
    fn buffer_len(&self) -> usize {
        FQ_CODEL_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = FqCodelBuffer::new(buffer);
        buffer.set_target(self.target);
        buffer.set_limit(self.limit);
        buffer.set_interval(self.interval);
        buffer.set_ecn(self.ecn);
        buffer.set_flows(self.flows);
        buffer.set_quantum(self.quantum);
        buffer.set_ce_threshold(self.ce_threshold);
        buffer.set_drop_batch_size(self.drop_batch_size);
        buffer.set_memory_limit(self.memory_limit);
    }
}

enum TcaFqCodel {
    Unspec = 0,
    Target,
    Limit,
    Interval,
    Ecn,
    Flows,
    Quantum,
    CeThreshold,
    DropBatchSize,
    MemoryLimit,
    Max,
}

impl From<u16> for TcaFqCodel {
    fn from(v: u16) -> Self {
        match v {
            0 => TcaFqCodel::Unspec,
            1 => TcaFqCodel::Target,
            2 => TcaFqCodel::Limit,
            3 => TcaFqCodel::Interval,
            4 => TcaFqCodel::Ecn,
            5 => TcaFqCodel::Flows,
            6 => TcaFqCodel::Quantum,
            7 => TcaFqCodel::CeThreshold,
            8 => TcaFqCodel::DropBatchSize,
            9 => TcaFqCodel::MemoryLimit,
            _ => TcaFqCodel::Max,
        }
    }
}

fn unmarshal_fq_codel_attr(data: &[u8]) -> Result<(u16, u32), DecodeError> {
    if data.len() < NLA_HEADER_LEN {
        return Err(DecodeError::from("fq_codel: invalid data"));
    }

    let length = u16::from_ne_bytes([data[0], data[1]]) as usize;
    let kind = u16::from_ne_bytes([data[2], data[3]]);

    if length > data.len() {
        return Err(DecodeError::from("fq_codel: invalid data"));
    }

    if length == 0 {
        return Err(DecodeError::from("fq_codel: empty data"));
    }

    if length < NLA_HEADER_LEN {
        return Err(DecodeError::from("fq_codel: invalid data"));
    }

    let payload_length = length - NLA_HEADER_LEN;
    if payload_length != ATTR_LEN {
        return Err(DecodeError::from("fq_codel: invalid data"));
    }
    let mut bytes = [0u8; ATTR_LEN];
    bytes.copy_from_slice(&data[NLA_HEADER_LEN..NLA_HEADER_LEN + ATTR_LEN]);

    Ok((kind, u32::from_ne_bytes(bytes)))
}

pub fn unmarshal_fq_codel(data: &[u8]) -> Result<FqCodel, DecodeError> {
    let mut fq = FqCodel::default();

    let length = data.len();
    let mut offset = 0;
    while offset < length {
        let buf = &data[offset..];
        let (kind, attr) = unmarshal_fq_codel_attr(buf)?;
        match TcaFqCodel::from(kind) {
            TcaFqCodel::Target => fq.target = attr,
            TcaFqCodel::Limit => fq.limit = attr,
            TcaFqCodel::Interval => fq.interval = attr,
            TcaFqCodel::Ecn => fq.ecn = attr,
            TcaFqCodel::Flows => fq.flows = attr,
            TcaFqCodel::Quantum => fq.quantum = attr,
            TcaFqCodel::CeThreshold => fq.ce_threshold = attr,
            TcaFqCodel::DropBatchSize => fq.drop_batch_size = attr,
            TcaFqCodel::MemoryLimit => fq.memory_limit = attr,
            _ => return Err(DecodeError::from("fq_codel: unknown attribute")),
        }
        offset += NLA_HEADER_LEN + ATTR_LEN;
    }
    Ok(fq)
}
