// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32, append_u64, parse_u32, parse_u64, DecodeError, Emitable,
    EncodeError, ErrorContext,
};

/// Rate estimator configuration (`struct gnet_estimator`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcRateEstimator {
    /// Sampling period.
    pub interval: i8,
    /// Log of measurement window weight.
    pub ewma_log: u8,
}

impl TcRateEstimator {
    pub const LENGTH: usize = 2;

    #[must_use]
    pub const fn new(interval: i8, ewma_log: u8) -> Self {
        Self { interval, ewma_log }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            return Err(DecodeError::buffer_too_small(
                payload.len(),
                Self::LENGTH,
            ));
        }
        Ok(Self {
            interval: payload[0] as i8,
            ewma_log: payload[1],
        })
    }
}

impl Emitable for TcRateEstimator {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.push(self.interval as u8);
        out.push(self.ewma_log);
        Ok(())
    }
}

/// Rate estimator statistics (`struct gnet_stats_rate_est`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcStatsRateEst {
    /// Current byte rate.
    pub bps: u32,
    /// Current packet rate.
    pub pps: u32,
}

impl TcStatsRateEst {
    pub const LENGTH: usize = 8;

    #[must_use]
    pub const fn new(bps: u32, pps: u32) -> Self {
        Self { bps, pps }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            return Err(DecodeError::buffer_too_small(
                payload.len(),
                Self::LENGTH,
            ));
        }
        Ok(Self {
            bps: parse_u32(&payload[0..4]).context("invalid rate est bps")?,
            pps: parse_u32(&payload[4..8]).context("invalid rate est pps")?,
        })
    }
}

impl Emitable for TcStatsRateEst {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.bps);
        append_u32(out, self.pps);
        Ok(())
    }
}

/// 64-bit rate estimator statistics (`struct gnet_stats_rate_est64`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcStatsRateEst64 {
    /// Current byte rate.
    pub bps: u64,
    /// Current packet rate.
    pub pps: u64,
}

impl TcStatsRateEst64 {
    pub const LENGTH: usize = 16;

    #[must_use]
    pub const fn new(bps: u64, pps: u64) -> Self {
        Self { bps, pps }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            return Err(DecodeError::buffer_too_small(
                payload.len(),
                Self::LENGTH,
            ));
        }
        Ok(Self {
            bps: parse_u64(&payload[0..8]).context("invalid rate est64 bps")?,
            pps: parse_u64(&payload[8..16])
                .context("invalid rate est64 pps")?,
        })
    }
}

impl Emitable for TcStatsRateEst64 {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u64(out, self.bps);
        append_u64(out, self.pps);
        Ok(())
    }
}
