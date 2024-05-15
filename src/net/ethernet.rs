use netlink_packet_utils::DecodeError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Mac([u8; 6]);
pub type MacMask = Mac;

impl AsRef<[u8; 6]> for Mac {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for Mac {
    fn from(val: [u8; 6]) -> Self {
        Self(val)
    }
}

impl From<Mac> for [u8; 6] {
    fn from(val: Mac) -> Self {
        val.0
    }
}

const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;
const ETH_TYPE_WAKE_ON_LAN: u16 = 0x0842;
const ETH_TYPE_STREAM_RESERVATION_PROTOCOL: u16 = 0x22EA;
const ETH_TYPE_AUDIO_VIDEO_TRANSPORT_PROTOCOL: u16 = 0x22F0;
const ETH_TYPE_IETF_TRILL_PROTOCOL: u16 = 0x22F3;
const ETH_TYPE_REVERSE_ARP: u16 = 0x8035;
const ETH_TYPE_APPLE_TALK: u16 = 0x809B;
const ETH_TYPE_APPLE_TALK_ADDRESS_RESOLUTION_PROTOCOL: u16 = 0x80F3;
const ETH_TYPE_VLAN: u16 = 0x8100;
const ETH_TYPE_SIMPLE_LOOP_PREVENTION_PROTOCOL: u16 = 0x8102;
const ETH_TYPE_VIRTUAL_LINK_AGGREGATION_CONTROL_PROTOCOL: u16 = 0x8103;
const ETH_TYPE_IPX: u16 = 0x8137;
const ETH_TYPE_QNX_QNET: u16 = 0x8204;
const ETH_TYPE_IPV6: u16 = 0x86DD;
const ETH_TYPE_ETHERNET_FLOW_CONTROL: u16 = 0x8808;
const ETH_TYPE_ETHERNET_SLOW_PROTOCOLS: u16 = 0x8809;
const ETH_TYPE_COBRA_NET: u16 = 0x8819;
const ETH_TYPE_MPLS_UNICAST: u16 = 0x8847;
const ETH_TYPE_MPLS_MULTICAST: u16 = 0x8848;
const ETH_TYPE_PPPOE_DISCOVERY: u16 = 0x8863;
const ETH_TYPE_PPPOE: u16 = 0x8864;
const ETH_TYPE_EAP_OVER_LAN: u16 = 0x888E;
const ETH_TYPE_PROFINET: u16 = 0x8892;
const ETH_TYPE_HYPER_SCSI: u16 = 0x889A;
const ETH_TYPE_ATA_OVER_ETHERNET: u16 = 0x88A2;
const ETH_TYPE_ETHER_CAT_PROTOCOL: u16 = 0x88A4;
const ETH_TYPE_QINQ: u16 = 0x88A8;
const ETH_TYPE_GOOSE: u16 = 0x88B8;
const ETH_TYPE_GSE_MANAGEMENT_SERVICES: u16 = 0x88B9;
const ETH_TYPE_SVSAMPLED_VALUE_TRANSMISSION: u16 = 0x88BA;
const ETH_TYPE_MIKRO_TIK_ROMON: u16 = 0x88BF;
const ETH_TYPE_LINK_LAYER_DISCOVERY_PROTOCOL: u16 = 0x88CC;
const ETH_TYPE_SERCOS_III: u16 = 0x88CD;
const ETH_TYPE_HOME_PLUG_GREEN_PHY: u16 = 0x88E1;
const ETH_TYPE_MEDIA_REDUNDANCY_PROTOCOL: u16 = 0x88E3;
const ETH_TYPE_MAC_SEC: u16 = 0x88E5;
const ETH_TYPE_PROVIDER_BACKBONE_BRIDGES: u16 = 0x88E7;
const ETH_TYPE_PTP: u16 = 0x88F7;
const ETH_TYPE_NC_SI: u16 = 0x88F8;
const ETH_TYPE_PARALLEL_REDUNDANCY_PROTOCOL: u16 = 0x88FB;
const ETH_TYPE_CFM: u16 = 0x8902;
const ETH_TYPE_FCOE: u16 = 0x8906;
const ETH_TYPE_FCOE_INITIALIZATION: u16 = 0x8914;
const ETH_TYPE_RO_CE: u16 = 0x8915;
const ETH_TYPE_TT_ETHERNET_PROTOCOL_CONTROL_FRAME: u16 = 0x891D;
const ETH_TYPE_HSR: u16 = 0x892F;
const ETH_TYPE_ETHERNET_CONFIGURATION_TESTING: u16 = 0x9000;
const ETH_TYPE_REDUNDANCY_TAG: u16 = 0xF1C1;

/// Ethernet Type (Ethertype)
///
/// Enum of Ethertypes found in ethernet frame headers.
/// The list is not exhaustive or authoritative and includes only the most
/// common Ethertypes.
/// The list is based on the [Ethernet Type Wikipedia page][1].
///
/// [1]: https://en.wikipedia.org/wiki/EtherType
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum Ethertype {
    IPv4 = ETH_TYPE_IPV4,
    Arp = ETH_TYPE_ARP,
    WakeOnLan = ETH_TYPE_WAKE_ON_LAN,
    StreamReservationProtocol = ETH_TYPE_STREAM_RESERVATION_PROTOCOL,
    AudioVideoTransportProtocol = ETH_TYPE_AUDIO_VIDEO_TRANSPORT_PROTOCOL,
    Trill = ETH_TYPE_IETF_TRILL_PROTOCOL,
    ReverseArp = ETH_TYPE_REVERSE_ARP,
    AppleTalk = ETH_TYPE_APPLE_TALK,
    AppleTalkAddressResolutionProtocol =
        ETH_TYPE_APPLE_TALK_ADDRESS_RESOLUTION_PROTOCOL,
    Vlan = ETH_TYPE_VLAN,
    SimpleLoopPreventionProtocol = ETH_TYPE_SIMPLE_LOOP_PREVENTION_PROTOCOL,
    VirtualLinkAggregationControlProtocol =
        ETH_TYPE_VIRTUAL_LINK_AGGREGATION_CONTROL_PROTOCOL,
    Ipx = ETH_TYPE_IPX,
    QnxQnet = ETH_TYPE_QNX_QNET,
    IPv6 = ETH_TYPE_IPV6,
    EthernetFlowControl = ETH_TYPE_ETHERNET_FLOW_CONTROL,
    EthernetSlowProtocols = ETH_TYPE_ETHERNET_SLOW_PROTOCOLS,
    CobraNet = ETH_TYPE_COBRA_NET,
    MplsUnicast = ETH_TYPE_MPLS_UNICAST,
    MplsMulticast = ETH_TYPE_MPLS_MULTICAST,
    PPPoEDiscovery = ETH_TYPE_PPPOE_DISCOVERY,
    PPPoE = ETH_TYPE_PPPOE,
    EapOverLan = ETH_TYPE_EAP_OVER_LAN,
    Profinet = ETH_TYPE_PROFINET,
    HyperScsi = ETH_TYPE_HYPER_SCSI,
    AtaOverEthernet = ETH_TYPE_ATA_OVER_ETHERNET,
    EtherCatProtocol = ETH_TYPE_ETHER_CAT_PROTOCOL,
    Qinq = ETH_TYPE_QINQ,
    Goose = ETH_TYPE_GOOSE,
    GseManagementServices = ETH_TYPE_GSE_MANAGEMENT_SERVICES,
    SvsampledValueTransmission = ETH_TYPE_SVSAMPLED_VALUE_TRANSMISSION,
    MikroTikRoMon = ETH_TYPE_MIKRO_TIK_ROMON,
    LinkLayerDiscoveryProtocol = ETH_TYPE_LINK_LAYER_DISCOVERY_PROTOCOL,
    SercosIII = ETH_TYPE_SERCOS_III,
    HomePlugGreenPhy = ETH_TYPE_HOME_PLUG_GREEN_PHY,
    MediaRedundancyProtocol = ETH_TYPE_MEDIA_REDUNDANCY_PROTOCOL,
    MACsec = ETH_TYPE_MAC_SEC,
    ProviderBackboneBridges = ETH_TYPE_PROVIDER_BACKBONE_BRIDGES,
    Ptp = ETH_TYPE_PTP,
    NcSi = ETH_TYPE_NC_SI,
    ParallelRedundancyProtocol = ETH_TYPE_PARALLEL_REDUNDANCY_PROTOCOL,
    Cfm = ETH_TYPE_CFM,
    FCoE = ETH_TYPE_FCOE,
    FCoEInitialization = ETH_TYPE_FCOE_INITIALIZATION,
    RoCE = ETH_TYPE_RO_CE,
    TtEthernetProtocolControlFrame =
        ETH_TYPE_TT_ETHERNET_PROTOCOL_CONTROL_FRAME,
    Hsr = ETH_TYPE_HSR,
    EthernetConfigurationTesting = ETH_TYPE_ETHERNET_CONFIGURATION_TESTING,
    RedundancyTag = ETH_TYPE_REDUNDANCY_TAG,
    Other(u16),
}

impl Ethertype {
    /// Returns the value as big-endian bytes.
    #[must_use]
    pub fn as_be_bytes(&self) -> [u8; 2] {
        self.as_ref().to_be_bytes()
    }
}

impl AsRef<u16> for Ethertype {
    fn as_ref(&self) -> &u16 {
        match self {
            Ethertype::IPv4 => &ETH_TYPE_IPV4,
            Ethertype::Arp => &ETH_TYPE_ARP,
            Ethertype::WakeOnLan => &ETH_TYPE_WAKE_ON_LAN,
            Ethertype::StreamReservationProtocol => {
                &ETH_TYPE_STREAM_RESERVATION_PROTOCOL
            }
            Ethertype::AudioVideoTransportProtocol => {
                &ETH_TYPE_AUDIO_VIDEO_TRANSPORT_PROTOCOL
            }
            Ethertype::Trill => &ETH_TYPE_IETF_TRILL_PROTOCOL,
            Ethertype::ReverseArp => &ETH_TYPE_REVERSE_ARP,
            Ethertype::AppleTalk => &ETH_TYPE_APPLE_TALK,
            Ethertype::AppleTalkAddressResolutionProtocol => {
                &ETH_TYPE_APPLE_TALK_ADDRESS_RESOLUTION_PROTOCOL
            }
            Ethertype::Vlan => &ETH_TYPE_VLAN,
            Ethertype::SimpleLoopPreventionProtocol => {
                &ETH_TYPE_SIMPLE_LOOP_PREVENTION_PROTOCOL
            }
            Ethertype::VirtualLinkAggregationControlProtocol => {
                &ETH_TYPE_VIRTUAL_LINK_AGGREGATION_CONTROL_PROTOCOL
            }
            Ethertype::Ipx => &ETH_TYPE_IPX,
            Ethertype::QnxQnet => &ETH_TYPE_QNX_QNET,
            Ethertype::IPv6 => &ETH_TYPE_IPV6,
            Ethertype::EthernetFlowControl => &ETH_TYPE_ETHERNET_FLOW_CONTROL,
            Ethertype::EthernetSlowProtocols => {
                &ETH_TYPE_ETHERNET_SLOW_PROTOCOLS
            }
            Ethertype::CobraNet => &ETH_TYPE_COBRA_NET,
            Ethertype::MplsUnicast => &ETH_TYPE_MPLS_UNICAST,
            Ethertype::MplsMulticast => &ETH_TYPE_MPLS_MULTICAST,
            Ethertype::PPPoEDiscovery => &ETH_TYPE_PPPOE_DISCOVERY,
            Ethertype::PPPoE => &ETH_TYPE_PPPOE,
            Ethertype::EapOverLan => &ETH_TYPE_EAP_OVER_LAN,
            Ethertype::Profinet => &ETH_TYPE_PROFINET,
            Ethertype::HyperScsi => &ETH_TYPE_HYPER_SCSI,
            Ethertype::AtaOverEthernet => &ETH_TYPE_ATA_OVER_ETHERNET,
            Ethertype::EtherCatProtocol => &ETH_TYPE_ETHER_CAT_PROTOCOL,
            Ethertype::Qinq => &ETH_TYPE_QINQ,
            Ethertype::Goose => &ETH_TYPE_GOOSE,
            Ethertype::GseManagementServices => {
                &ETH_TYPE_GSE_MANAGEMENT_SERVICES
            }
            Ethertype::SvsampledValueTransmission => {
                &ETH_TYPE_SVSAMPLED_VALUE_TRANSMISSION
            }
            Ethertype::MikroTikRoMon => &ETH_TYPE_MIKRO_TIK_ROMON,
            Ethertype::LinkLayerDiscoveryProtocol => {
                &ETH_TYPE_LINK_LAYER_DISCOVERY_PROTOCOL
            }
            Ethertype::SercosIII => &ETH_TYPE_SERCOS_III,
            Ethertype::HomePlugGreenPhy => &ETH_TYPE_HOME_PLUG_GREEN_PHY,
            Ethertype::MediaRedundancyProtocol => {
                &ETH_TYPE_MEDIA_REDUNDANCY_PROTOCOL
            }
            Ethertype::MACsec => &ETH_TYPE_MAC_SEC,
            Ethertype::ProviderBackboneBridges => {
                &ETH_TYPE_PROVIDER_BACKBONE_BRIDGES
            }
            Ethertype::Ptp => &ETH_TYPE_PTP,
            Ethertype::NcSi => &ETH_TYPE_NC_SI,
            Ethertype::ParallelRedundancyProtocol => {
                &ETH_TYPE_PARALLEL_REDUNDANCY_PROTOCOL
            }
            Ethertype::Cfm => &ETH_TYPE_CFM,
            Ethertype::FCoE => &ETH_TYPE_FCOE,
            Ethertype::FCoEInitialization => &ETH_TYPE_FCOE_INITIALIZATION,
            Ethertype::RoCE => &ETH_TYPE_RO_CE,
            Ethertype::TtEthernetProtocolControlFrame => {
                &ETH_TYPE_TT_ETHERNET_PROTOCOL_CONTROL_FRAME
            }
            Ethertype::Hsr => &ETH_TYPE_HSR,
            Ethertype::EthernetConfigurationTesting => {
                &ETH_TYPE_ETHERNET_CONFIGURATION_TESTING
            }
            Ethertype::RedundancyTag => &ETH_TYPE_REDUNDANCY_TAG,
            Ethertype::Other(other) => other,
        }
    }
}

impl From<u16> for Ethertype {
    fn from(val: u16) -> Self {
        match val {
            ETH_TYPE_IPV4 => Ethertype::IPv4,
            ETH_TYPE_ARP => Ethertype::Arp,
            ETH_TYPE_WAKE_ON_LAN => Ethertype::WakeOnLan,
            ETH_TYPE_STREAM_RESERVATION_PROTOCOL => {
                Ethertype::StreamReservationProtocol
            }
            ETH_TYPE_AUDIO_VIDEO_TRANSPORT_PROTOCOL => {
                Ethertype::AudioVideoTransportProtocol
            }
            ETH_TYPE_IETF_TRILL_PROTOCOL => Ethertype::Trill,
            ETH_TYPE_REVERSE_ARP => Ethertype::ReverseArp,
            ETH_TYPE_APPLE_TALK => Ethertype::AppleTalk,
            ETH_TYPE_APPLE_TALK_ADDRESS_RESOLUTION_PROTOCOL => {
                Ethertype::AppleTalkAddressResolutionProtocol
            }
            ETH_TYPE_VLAN => Ethertype::Vlan,
            ETH_TYPE_SIMPLE_LOOP_PREVENTION_PROTOCOL => {
                Ethertype::SimpleLoopPreventionProtocol
            }
            ETH_TYPE_VIRTUAL_LINK_AGGREGATION_CONTROL_PROTOCOL => {
                Ethertype::VirtualLinkAggregationControlProtocol
            }
            ETH_TYPE_IPX => Ethertype::Ipx,
            ETH_TYPE_QNX_QNET => Ethertype::QnxQnet,
            ETH_TYPE_IPV6 => Ethertype::IPv6,
            ETH_TYPE_ETHERNET_FLOW_CONTROL => Ethertype::EthernetFlowControl,
            ETH_TYPE_ETHERNET_SLOW_PROTOCOLS => {
                Ethertype::EthernetSlowProtocols
            }
            ETH_TYPE_COBRA_NET => Ethertype::CobraNet,
            ETH_TYPE_MPLS_UNICAST => Ethertype::MplsUnicast,
            ETH_TYPE_MPLS_MULTICAST => Ethertype::MplsMulticast,
            ETH_TYPE_PPPOE_DISCOVERY => Ethertype::PPPoEDiscovery,
            ETH_TYPE_PPPOE => Ethertype::PPPoE,
            ETH_TYPE_EAP_OVER_LAN => Ethertype::EapOverLan,
            ETH_TYPE_PROFINET => Ethertype::Profinet,
            ETH_TYPE_HYPER_SCSI => Ethertype::HyperScsi,
            ETH_TYPE_ATA_OVER_ETHERNET => Ethertype::AtaOverEthernet,
            ETH_TYPE_ETHER_CAT_PROTOCOL => Ethertype::EtherCatProtocol,
            ETH_TYPE_QINQ => Ethertype::Qinq,
            ETH_TYPE_GOOSE => Ethertype::Goose,
            ETH_TYPE_GSE_MANAGEMENT_SERVICES => {
                Ethertype::GseManagementServices
            }
            ETH_TYPE_SVSAMPLED_VALUE_TRANSMISSION => {
                Ethertype::SvsampledValueTransmission
            }
            ETH_TYPE_MIKRO_TIK_ROMON => Ethertype::MikroTikRoMon,
            ETH_TYPE_LINK_LAYER_DISCOVERY_PROTOCOL => {
                Ethertype::LinkLayerDiscoveryProtocol
            }
            ETH_TYPE_SERCOS_III => Ethertype::SercosIII,
            ETH_TYPE_HOME_PLUG_GREEN_PHY => Ethertype::HomePlugGreenPhy,
            ETH_TYPE_MEDIA_REDUNDANCY_PROTOCOL => {
                Ethertype::MediaRedundancyProtocol
            }
            ETH_TYPE_MAC_SEC => Ethertype::MACsec,
            ETH_TYPE_PROVIDER_BACKBONE_BRIDGES => {
                Ethertype::ProviderBackboneBridges
            }
            ETH_TYPE_PTP => Ethertype::Ptp,
            ETH_TYPE_NC_SI => Ethertype::NcSi,
            ETH_TYPE_PARALLEL_REDUNDANCY_PROTOCOL => {
                Ethertype::ParallelRedundancyProtocol
            }
            ETH_TYPE_CFM => Ethertype::Cfm,
            ETH_TYPE_FCOE => Ethertype::FCoE,
            ETH_TYPE_FCOE_INITIALIZATION => Ethertype::FCoEInitialization,
            ETH_TYPE_RO_CE => Ethertype::RoCE,
            ETH_TYPE_TT_ETHERNET_PROTOCOL_CONTROL_FRAME => {
                Ethertype::TtEthernetProtocolControlFrame
            }
            ETH_TYPE_HSR => Ethertype::Hsr,
            ETH_TYPE_ETHERNET_CONFIGURATION_TESTING => {
                Ethertype::EthernetConfigurationTesting
            }
            ETH_TYPE_REDUNDANCY_TAG => Ethertype::RedundancyTag,
            _ => Self::Other(val),
        }
    }
}

impl From<Ethertype> for u16 {
    fn from(val: Ethertype) -> Self {
        *val.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VlanId(u16);

impl VlanId {
    /// Creates a new `VlanId` value.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is greater than or equal to 4096.
    pub fn new(id: u16) -> Result<Self, DecodeError> {
        if id >= 4096 {
            return Err(DecodeError::from("VLAN ID must be less than 4096"));
        }
        Ok(Self(id))
    }
}

impl TryFrom<u16> for VlanId {
    type Error = DecodeError;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

impl AsRef<u16> for VlanId {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl From<VlanId> for u16 {
    fn from(val: VlanId) -> Self {
        val.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VlanPrio(u8);

impl VlanPrio {
    /// Creates a new `VlanPrio` value.
    ///
    /// # Errors
    ///
    /// Returns an error if the priority is greater than 7.
    pub fn new(prio: u8) -> Result<Self, DecodeError> {
        if prio > Self::HIGHEST.into() {
            return Err(DecodeError::from("VLAN priority must be less than 8"));
        }
        Ok(Self(prio))
    }

    const BEST_EFFORT: Self = Self(0);
    const HIGHEST: Self = Self(7);
}

impl TryFrom<u8> for VlanPrio {
    type Error = DecodeError;

    fn try_from(prio: u8) -> Result<Self, Self::Error> {
        Self::new(prio)
    }
}

impl AsRef<u8> for VlanPrio {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl From<VlanPrio> for u8 {
    fn from(val: VlanPrio) -> Self {
        val.0
    }
}

impl Default for VlanPrio {
    fn default() -> Self {
        Self::BEST_EFFORT
    }
}
