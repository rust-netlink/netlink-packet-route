use netlink_packet_utils::DecodeError;

/// A VXLAN Network Identifier (VNI)
///
/// VXLAN Network Identifiers (VNIs) are 24-bit identifiers that are used to
/// multiplex multiple VXLAN tunnels over the same physical network.
/// VNIs are used to identify the logical network that a VXLAN packet belongs
/// to.
///
/// See [RFC 7348][1] for more information.
///
/// This type is a thin wrapper around `u32` that ensures that the VNI is
/// non-zero and less than 2^24.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc7348
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Vni(u32);

impl Vni {
    /// Creates a new `Vni` value.
    ///
    /// # Errors
    /// Returns an error if the VNI is zero or greater than 2^24.
    pub fn new(vni: u32) -> Result<Self, DecodeError> {
        Self::try_from(vni)
    }

    /// Creates a new `Vni` value without checking the VNI value.
    ///
    /// # Warning
    /// You must ensure that the VNI is non-zero and less than 2^24, or you may
    /// produce semantically invalid `Vni` values.
    #[must_use]
    pub fn new_unchecked(vni: u32) -> Self {
        Self(vni)
    }

    /// The largest legal VXLAN VNI
    pub const MAX: Self = Self((1 << 24) - 1);
    /// The smallest legal VXLAN VNI
    pub const MIN: Self = Self(1);
}

impl TryFrom<u32> for Vni {
    type Error = DecodeError;

    /// Creates a new `Vni` value from an `u32`.
    ///
    /// # Errors
    /// Returns an error if the VNI is zero or greater than or equal to 2^24.
    fn try_from(vni: u32) -> Result<Self, Self::Error> {
        if vni == 0 {
            return Err(Self::Error::from("VNI must be non-zero"));
        }
        if vni >= (1 << 24) {
            return Err(Self::Error::from(format!(
                "VNI must be less than 2^24, received {vni}"
            )));
        }
        Ok(Self(vni))
    }
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        vni.0
    }
}

impl AsRef<u32> for Vni {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_vni_is_invalid() {
        assert!(Vni::new(0).is_err());
    }

    #[test]
    fn min_vni_is_valid() {
        assert!(Vni::new(Vni::MIN.0).is_ok());
    }
    
    #[test]
    fn max_vni_is_valid() {
        assert!(Vni::new(Vni::MAX.0).is_ok());
    }

    #[test]
    fn vni_greater_than_max_is_invalid() {
        assert!(Vni::new(Vni::MAX.0 + 1).is_err());
    }

    #[test]
    fn vni_is_converted_to_u32() {
        let vni = Vni::new_unchecked(42);
        assert_eq!(u32::from(vni), 42);
    }
}
