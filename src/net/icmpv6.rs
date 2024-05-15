const DESTINATION_UNREACHABLE: u8 = 1;
const PACKET_TOO_BIG: u8 = 2;
const TIME_EXCEEDED: u8 = 3;
const PARAMETER_PROBLEM: u8 = 4;
const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;
const MULTICAST_LISTENER_QUERY: u8 = 130;
const MULTICAST_LISTENER_REPORT: u8 = 131;
const MULTICAST_LISTENER_DONE: u8 = 132;
const ROUTER_SOLICITATION: u8 = 133;
const ROUTER_ADVERTISEMENT: u8 = 134;
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;
const REDIRECT_MESSAGE: u8 = 137;
const ROUTER_RENUMBERING: u8 = 138;
const ICMP_NODE_INFORMATION_QUERY: u8 = 139;
const ICMP_NODE_INFORMATION_RESPONSE: u8 = 140;
const INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE: u8 = 141;
const INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE: u8 = 142;
const VERSION2_MULTICAST_LISTENER_REPORT: u8 = 143;
const HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE: u8 = 144;
const HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE: u8 = 145;
const MOBILE_PREFIX_SOLICITATION: u8 = 146;
const MOBILE_PREFIX_ADVERTISEMENT: u8 = 147;
const CERTIFICATION_PATH_SOLICITATION_MESSAGE: u8 = 148;
const CERTIFICATION_PATH_ADVERTISEMENT_MESSAGE: u8 = 149;
const EXPERIMENTAL_MOBILITY_PROTOCOLS: u8 = 150;
const MULTICAST_ROUTER_ADVERTISEMENT: u8 = 151;
const MULTICAST_ROUTER_SOLICITATION: u8 = 152;
const MULTICAST_ROUTER_TERMINATION: u8 = 153;
const FMIPV6_MESSAGES: u8 = 154;
const RPLCONTROL_MESSAGE: u8 = 155;
const ILNPV6_LOCATOR_UPDATE_MESSAGE: u8 = 156;
const DUPLICATE_ADDRESS_REQUEST: u8 = 157;
const DUPLICATE_ADDRESS_CONFIRMATION: u8 = 158;
const MPLCONTROL_MESSAGE: u8 = 159;
const EXTENDED_ECHO_REQUEST: u8 = 160;
const EXTENDED_ECHO_REPLY: u8 = 161;

/// Enum of `ICMPv6` message types.
///
/// This enum is not exhaustive.
/// List sourced from [iana.org][1]
///
/// [1]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Type {
    DestinationUnreachable = DESTINATION_UNREACHABLE,
    PacketTooBig = PACKET_TOO_BIG,
    TimeExceeded = TIME_EXCEEDED,
    ParameterProblem = PARAMETER_PROBLEM,
    EchoRequest = ECHO_REQUEST,
    EchoReply = ECHO_REPLY,
    MulticastListenerQuery = MULTICAST_LISTENER_QUERY,
    MulticastListenerReport = MULTICAST_LISTENER_REPORT,
    MulticastListenerDone = MULTICAST_LISTENER_DONE,
    RouterSolicitation = ROUTER_SOLICITATION,
    RouterAdvertisement = ROUTER_ADVERTISEMENT,
    NeighborSolicitation = NEIGHBOR_SOLICITATION,
    NeighborAdvertisement = NEIGHBOR_ADVERTISEMENT,
    RedirectMessage = REDIRECT_MESSAGE,
    RouterRenumbering = ROUTER_RENUMBERING,
    IcmpNodeInformationQuery = ICMP_NODE_INFORMATION_QUERY,
    IcmpNodeInformationResponse = ICMP_NODE_INFORMATION_RESPONSE,
    InverseNeighborDiscoverySolicitationMessage =
        INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE,
    InverseNeighborDiscoveryAdvertisementMessage =
        INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE,
    Version2MulticastListenerReport = VERSION2_MULTICAST_LISTENER_REPORT,
    HomeAgentAddressDiscoveryRequestMessage =
        HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE,
    HomeAgentAddressDiscoveryReplyMessage =
        HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE,
    MobilePrefixSolicitation = MOBILE_PREFIX_SOLICITATION,
    MobilePrefixAdvertisement = MOBILE_PREFIX_ADVERTISEMENT,
    CertificationPathSolicitationMessage =
        CERTIFICATION_PATH_SOLICITATION_MESSAGE,
    CertificationPathAdvertisementMessage =
        CERTIFICATION_PATH_ADVERTISEMENT_MESSAGE,
    ExperimentalMobilityProtocols = EXPERIMENTAL_MOBILITY_PROTOCOLS,
    MulticastRouterAdvertisement = MULTICAST_ROUTER_ADVERTISEMENT,
    MulticastRouterSolicitation = MULTICAST_ROUTER_SOLICITATION,
    MulticastRouterTermination = MULTICAST_ROUTER_TERMINATION,
    FMIPv6Messages = FMIPV6_MESSAGES,
    RPLControlMessage = RPLCONTROL_MESSAGE,
    ILNPv6LocatorUpdateMessage = ILNPV6_LOCATOR_UPDATE_MESSAGE,
    DuplicateAddressRequest = DUPLICATE_ADDRESS_REQUEST,
    DuplicateAddressConfirmation = DUPLICATE_ADDRESS_CONFIRMATION,
    MPLControlMessage = MPLCONTROL_MESSAGE,
    ExtendedEchoRequest = EXTENDED_ECHO_REQUEST,
    ExtendedEchoReply = EXTENDED_ECHO_REPLY,
    Other(u8),
}

impl AsRef<u8> for Type {
    fn as_ref(&self) -> &u8 {
        match self {
            Type::DestinationUnreachable => &DESTINATION_UNREACHABLE,
            Type::PacketTooBig => &PACKET_TOO_BIG,
            Type::TimeExceeded => &TIME_EXCEEDED,
            Type::ParameterProblem => &PARAMETER_PROBLEM,
            Type::EchoRequest => &ECHO_REQUEST,
            Type::EchoReply => &ECHO_REPLY,
            Type::MulticastListenerQuery => &MULTICAST_LISTENER_QUERY,
            Type::MulticastListenerReport => &MULTICAST_LISTENER_REPORT,
            Type::MulticastListenerDone => &MULTICAST_LISTENER_DONE,
            Type::RouterSolicitation => &ROUTER_SOLICITATION,
            Type::RouterAdvertisement => &ROUTER_ADVERTISEMENT,
            Type::NeighborSolicitation => &NEIGHBOR_SOLICITATION,
            Type::NeighborAdvertisement => &NEIGHBOR_ADVERTISEMENT,
            Type::RedirectMessage => &REDIRECT_MESSAGE,
            Type::RouterRenumbering => &ROUTER_RENUMBERING,
            Type::IcmpNodeInformationQuery => &ICMP_NODE_INFORMATION_QUERY,
            Type::IcmpNodeInformationResponse => {
                &ICMP_NODE_INFORMATION_RESPONSE
            }
            Type::InverseNeighborDiscoverySolicitationMessage => {
                &INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE
            }
            Type::InverseNeighborDiscoveryAdvertisementMessage => {
                &INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE
            }
            Type::Version2MulticastListenerReport => {
                &VERSION2_MULTICAST_LISTENER_REPORT
            }
            Type::HomeAgentAddressDiscoveryRequestMessage => {
                &HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE
            }
            Type::HomeAgentAddressDiscoveryReplyMessage => {
                &HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE
            }
            Type::MobilePrefixSolicitation => &MOBILE_PREFIX_SOLICITATION,
            Type::MobilePrefixAdvertisement => &MOBILE_PREFIX_ADVERTISEMENT,
            Type::CertificationPathSolicitationMessage => {
                &CERTIFICATION_PATH_SOLICITATION_MESSAGE
            }
            Type::CertificationPathAdvertisementMessage => {
                &CERTIFICATION_PATH_ADVERTISEMENT_MESSAGE
            }
            Type::ExperimentalMobilityProtocols => {
                &EXPERIMENTAL_MOBILITY_PROTOCOLS
            }
            Type::MulticastRouterAdvertisement => {
                &MULTICAST_ROUTER_ADVERTISEMENT
            }
            Type::MulticastRouterSolicitation => &MULTICAST_ROUTER_SOLICITATION,
            Type::MulticastRouterTermination => &MULTICAST_ROUTER_TERMINATION,
            Type::FMIPv6Messages => &FMIPV6_MESSAGES,
            Type::RPLControlMessage => &RPLCONTROL_MESSAGE,
            Type::ILNPv6LocatorUpdateMessage => &ILNPV6_LOCATOR_UPDATE_MESSAGE,
            Type::DuplicateAddressRequest => &DUPLICATE_ADDRESS_REQUEST,
            Type::DuplicateAddressConfirmation => {
                &DUPLICATE_ADDRESS_CONFIRMATION
            }
            Type::MPLControlMessage => &MPLCONTROL_MESSAGE,
            Type::ExtendedEchoRequest => &EXTENDED_ECHO_REQUEST,
            Type::ExtendedEchoReply => &EXTENDED_ECHO_REPLY,
            Type::Other(x) => x,
        }
    }
}

impl From<u8> for Type {
    fn from(value: u8) -> Self {
        match value {
            DESTINATION_UNREACHABLE => Self::DestinationUnreachable,
            PACKET_TOO_BIG => Self::PacketTooBig,
            TIME_EXCEEDED => Self::TimeExceeded,
            PARAMETER_PROBLEM => Self::ParameterProblem,
            ECHO_REQUEST => Self::EchoRequest,
            ECHO_REPLY => Self::EchoReply,
            MULTICAST_LISTENER_QUERY => Self::MulticastListenerQuery,
            MULTICAST_LISTENER_REPORT => Self::MulticastListenerReport,
            MULTICAST_LISTENER_DONE => Self::MulticastListenerDone,
            ROUTER_SOLICITATION => Self::RouterSolicitation,
            ROUTER_ADVERTISEMENT => Self::RouterAdvertisement,
            NEIGHBOR_SOLICITATION => Self::NeighborSolicitation,
            NEIGHBOR_ADVERTISEMENT => Self::NeighborAdvertisement,
            REDIRECT_MESSAGE => Self::RedirectMessage,
            ROUTER_RENUMBERING => Self::RouterRenumbering,
            ICMP_NODE_INFORMATION_QUERY => Self::IcmpNodeInformationQuery,
            ICMP_NODE_INFORMATION_RESPONSE => Self::IcmpNodeInformationResponse,
            INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE => {
                Self::InverseNeighborDiscoverySolicitationMessage
            }
            INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE => {
                Self::InverseNeighborDiscoveryAdvertisementMessage
            }
            VERSION2_MULTICAST_LISTENER_REPORT => {
                Self::Version2MulticastListenerReport
            }
            HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE => {
                Self::HomeAgentAddressDiscoveryRequestMessage
            }
            HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE => {
                Self::HomeAgentAddressDiscoveryReplyMessage
            }
            MOBILE_PREFIX_SOLICITATION => Self::MobilePrefixSolicitation,
            MOBILE_PREFIX_ADVERTISEMENT => Self::MobilePrefixAdvertisement,
            CERTIFICATION_PATH_SOLICITATION_MESSAGE => {
                Self::CertificationPathSolicitationMessage
            }
            CERTIFICATION_PATH_ADVERTISEMENT_MESSAGE => {
                Self::CertificationPathAdvertisementMessage
            }
            EXPERIMENTAL_MOBILITY_PROTOCOLS => {
                Self::ExperimentalMobilityProtocols
            }
            MULTICAST_ROUTER_ADVERTISEMENT => {
                Self::MulticastRouterAdvertisement
            }
            MULTICAST_ROUTER_SOLICITATION => Self::MulticastRouterSolicitation,
            MULTICAST_ROUTER_TERMINATION => Self::MulticastRouterTermination,
            FMIPV6_MESSAGES => Self::FMIPv6Messages,
            RPLCONTROL_MESSAGE => Self::RPLControlMessage,
            ILNPV6_LOCATOR_UPDATE_MESSAGE => Self::ILNPv6LocatorUpdateMessage,
            DUPLICATE_ADDRESS_REQUEST => Self::DuplicateAddressRequest,
            DUPLICATE_ADDRESS_CONFIRMATION => {
                Self::DuplicateAddressConfirmation
            }
            MPLCONTROL_MESSAGE => Self::MPLControlMessage,
            EXTENDED_ECHO_REQUEST => Self::ExtendedEchoRequest,
            EXTENDED_ECHO_REPLY => Self::ExtendedEchoReply,
            x => Self::Other(x),
        }
    }
}

impl From<Type> for u8 {
    fn from(value: Type) -> Self {
        *value.as_ref()
    }
}

pub type Code = u8;
