use netlink_packet_utils::DecodeError;

/// An identifier for an encapsulation key used by a tunnel.
///
/// Examples include a VNIs for VXLAN and Geneve tunnels, ERSPAN/GRE keys, and
/// GTP tunnel keys.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EncKeyId(u32);

impl EncKeyId {
    /// Create a new `EncKeyId` without checking the validity of the ID value.
    ///
    /// # Safety
    ///
    /// Failure to ensure the ID is within the valid range for the tunnel in
    /// question may lead to semantically invalid netlink messages.
    ///
    /// If you know the tunnel type (e.g., vxlan) and wish to confirm that the
    /// ID is within the valid range of values for that tunnel type, use the
    /// corresponding new method (e.g., `new_vxlan_vni`).
    #[must_use]
    pub const fn new_unchecked(id: u32) -> Self {
        Self(id)
    }

    /// Create a new `EncKeyId` and confirm that it is within the valid range
    /// of vxlan vni values.
    ///
    /// # Errors
    /// Returns an error if the ID is zero or greater than or equal to 2^24.
    pub fn new_vxlan_vni(id: u32) -> Result<Self, DecodeError> {
        crate::net::vxlan::Vni::new(id).map(Into::into)
    }

    /// Create a new `EncKeyId` and confirm that it is within the valid range
    /// of geneve vni values.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is greater than or equal to 2^24.
    pub fn new_geneve_vni(id: u32) -> Result<Self, DecodeError> {
        match Self::new_nbit::<24>(id) {
            Ok(id) => Ok(id),
            Err(_) => Err(DecodeError::from(
                "Geneve VNI must be less than 2^24, received {id}",
            )),
        }
    }

    /// Create a new `EncKeyId` in the space of valid GRE keys.
    ///
    /// # Safety
    ///
    /// Since GRE keys are 32 bits and all values are legal, this method is not
    /// failable.
    #[must_use]
    pub fn new_gre_key(id: u32) -> Self {
        Self(id)
    }

    /// Create a new `EncKeyId` and confirm that it is within the valid range
    /// of gtp tunnel key values.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is zero.
    pub fn new_gtp_key(id: u32) -> Result<Self, DecodeError> {
        if id == 0 {
            return Err(DecodeError::from(
                "zero is not a legal GTP tunnel key",
            ));
        }
        Ok(Self(id))
    }

    /// Create a new `EncKeyId` and confirm that it is within the valid range
    /// of N bit values.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is greater than or equal to 2^N.
    const fn new_nbit<const N: usize>(id: u32) -> Result<Self, KeyTooLarge> {
        if id >= (1 << N) {
            return Err(KeyTooLarge);
        };
        Ok(Self(id))
    }
}

impl From<EncKeyId> for u32 {
    fn from(id: EncKeyId) -> u32 {
        id.0
    }
}

impl AsRef<u32> for EncKeyId {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl From<u32> for EncKeyId {
    /// Convert `u32` to an `EncKeyId`.
    ///
    /// # Safety
    ///
    /// This conversion is infallible but may produce a semantically invalid key
    /// depending on the tunnel type.
    ///
    /// If you know the tunnel type (e.g., vxlan) and wish to confirm that the
    /// ID is within the valid range of values for that tunnel type, use the
    /// corresponding "new" method on the `EncKeyId` type (e.g.,
    /// `EncKeyId::new_vxlan_vni`).
    fn from(id: u32) -> Self {
        Self(id)
    }
}

#[derive(Debug)]
#[must_use]
struct KeyTooLarge;

impl From<crate::net::vxlan::Vni> for EncKeyId {
    fn from(vni: crate::net::vxlan::Vni) -> Self {
        Self(vni.into())
    }
}
