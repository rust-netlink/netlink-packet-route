const ECHO_REPLY: u8 = 0;
const DESTINATION_UNREACHABLE: u8 = 3;
const SOURCE_QUENCH: u8 = 4; // deprecated by iana
const REDIRECT: u8 = 5;
const ALTERNATE_HOST_ADDRESS: u8 = 6; // deprecated by iana
const ECHO_REQUEST: u8 = 8;
const ROUTER_ADVERTISEMENT: u8 = 9;
const ROUTER_SOLICITATION: u8 = 10;
const TIME_EXCEEDED: u8 = 11;
const PARAMETER_PROBLEM: u8 = 12;
const TIMESTAMP_REQUEST: u8 = 13;
const TIMESTAMP_REPLY: u8 = 14;
const INFORMATION_REQUEST: u8 = 15; // deprecated by iana
const INFORMATION_REPLY: u8 = 16; // deprecated by iana
const ADDRESS_MASK_REQUEST: u8 = 17; // deprecated by iana
const ADDRESS_MASK_REPLY: u8 = 18; // deprecated by iana
const TRACEROUTE: u8 = 30; // deprecated by iana
const DATAGRAM_CONVERSION_ERROR: u8 = 31; // deprecated by iana
const MOBILE_HOST_REDIRECT: u8 = 32; // deprecated by iana
const IPV6_WHERE_ARE_YOU: u8 = 33; // deprecated by iana
const IPV6_IAM_HERE: u8 = 34; // deprecated by iana
const MOBILE_REGISTRATION_REQUEST: u8 = 35; // deprecated by iana
const MOBILE_REGISTRATION_REPLY: u8 = 36; // deprecated by iana
const DOMAIN_NAME_REQUEST: u8 = 37; // deprecated by iana
const DOMAIN_NAME_REPLY: u8 = 38; // deprecated by iana
const SKIP: u8 = 39; // deprecated by iana
const PHOTURIS: u8 = 40;
const EXTENDED_ECHO_REQUEST: u8 = 42;
const EXTENDED_ECHO_REPLY: u8 = 43;

/// Enum of `ICMPv4` message types.
///
/// This enum is non-exhaustive as more `Type`s may be added in the future by
/// the IANA.
///
/// Codes sourced from [iana.org][1]
///
/// [1]: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Type {
    EchoReply = ECHO_REPLY,
    DestinationUnreachable = DESTINATION_UNREACHABLE,
    SourceQuench = SOURCE_QUENCH, // deprecated by iana
    Redirect = REDIRECT,
    AlternateHostAddress = ALTERNATE_HOST_ADDRESS, // deprecated by iana
    EchoRequest = ECHO_REQUEST,
    RouterAdvertisement = ROUTER_ADVERTISEMENT,
    RouterSolicitation = ROUTER_SOLICITATION,
    TimeExceeded = TIME_EXCEEDED,
    ParameterProblem = PARAMETER_PROBLEM,
    TimestampRequest = TIMESTAMP_REQUEST,
    TimestampReply = TIMESTAMP_REPLY,
    InformationRequest = INFORMATION_REQUEST, // deprecated by iana
    InformationReply = INFORMATION_REPLY,     // deprecated by iana
    AddressMaskRequest = ADDRESS_MASK_REQUEST, // deprecated by iana
    AddressMaskReply = ADDRESS_MASK_REPLY,    // deprecated by iana
    Traceroute = TRACEROUTE,                  // deprecated by iana
    DatagramConversionError = DATAGRAM_CONVERSION_ERROR, // deprecated by iana
    MobileHostRedirect = MOBILE_HOST_REDIRECT, // deprecated by iana
    Ipv6WhereAreYou = IPV6_WHERE_ARE_YOU,     // deprecated by iana
    Ipv6IAmHere = IPV6_IAM_HERE,              // deprecated by iana
    MobileRegistrationRequest = MOBILE_REGISTRATION_REQUEST, /* deprecated
                                               * by iana */
    MobileRegistrationReply = MOBILE_REGISTRATION_REPLY, // deprecated by iana
    DomainNameRequest = DOMAIN_NAME_REQUEST,             // deprecated by iana
    DomainNameReply = DOMAIN_NAME_REPLY,                 // deprecated by iana
    Skip = SKIP,                                         // deprecated by iana
    Photuris = PHOTURIS,
    ExtendedEchoRequest = EXTENDED_ECHO_REQUEST,
    ExtendedEchoReply = EXTENDED_ECHO_REPLY,
    Other(u8),
}

impl AsRef<u8> for Type {
    fn as_ref(&self) -> &u8 {
        match self {
            Type::EchoReply => &ECHO_REPLY,
            Type::DestinationUnreachable => &DESTINATION_UNREACHABLE,
            Type::SourceQuench => &SOURCE_QUENCH,
            Type::Redirect => &REDIRECT,
            Type::AlternateHostAddress => &ALTERNATE_HOST_ADDRESS,
            Type::EchoRequest => &ECHO_REQUEST,
            Type::RouterAdvertisement => &ROUTER_ADVERTISEMENT,
            Type::RouterSolicitation => &ROUTER_SOLICITATION,
            Type::TimeExceeded => &TIME_EXCEEDED,
            Type::ParameterProblem => &PARAMETER_PROBLEM,
            Type::TimestampRequest => &TIMESTAMP_REQUEST,
            Type::TimestampReply => &TIMESTAMP_REPLY,
            Type::InformationRequest => &INFORMATION_REQUEST,
            Type::InformationReply => &INFORMATION_REPLY,
            Type::AddressMaskRequest => &ADDRESS_MASK_REQUEST,
            Type::AddressMaskReply => &ADDRESS_MASK_REPLY,
            Type::Traceroute => &TRACEROUTE,
            Type::DatagramConversionError => &DATAGRAM_CONVERSION_ERROR,
            Type::MobileHostRedirect => &MOBILE_HOST_REDIRECT,
            Type::Ipv6WhereAreYou => &IPV6_WHERE_ARE_YOU,
            Type::Ipv6IAmHere => &IPV6_IAM_HERE,
            Type::MobileRegistrationRequest => &MOBILE_REGISTRATION_REQUEST,
            Type::MobileRegistrationReply => &MOBILE_REGISTRATION_REPLY,
            Type::DomainNameRequest => &DOMAIN_NAME_REQUEST,
            Type::DomainNameReply => &DOMAIN_NAME_REPLY,
            Type::Skip => &SKIP,
            Type::Photuris => &PHOTURIS,
            Type::ExtendedEchoRequest => &EXTENDED_ECHO_REQUEST,
            Type::ExtendedEchoReply => &EXTENDED_ECHO_REPLY,
            Type::Other(x) => x,
        }
    }
}

impl From<u8> for Type {
    fn from(value: u8) -> Self {
        match value {
            ECHO_REPLY => Type::EchoReply,
            DESTINATION_UNREACHABLE => Type::DestinationUnreachable,
            SOURCE_QUENCH => Type::SourceQuench,
            REDIRECT => Type::Redirect,
            ALTERNATE_HOST_ADDRESS => Type::AlternateHostAddress,
            ECHO_REQUEST => Type::EchoRequest,
            ROUTER_ADVERTISEMENT => Type::RouterAdvertisement,
            ROUTER_SOLICITATION => Type::RouterSolicitation,
            TIME_EXCEEDED => Type::TimeExceeded,
            PARAMETER_PROBLEM => Type::ParameterProblem,
            TIMESTAMP_REQUEST => Type::TimestampRequest,
            TIMESTAMP_REPLY => Type::TimestampReply,
            INFORMATION_REQUEST => Type::InformationRequest,
            INFORMATION_REPLY => Type::InformationReply,
            ADDRESS_MASK_REQUEST => Type::AddressMaskRequest,
            ADDRESS_MASK_REPLY => Type::AddressMaskReply,
            TRACEROUTE => Type::Traceroute,
            DATAGRAM_CONVERSION_ERROR => Type::DatagramConversionError,
            MOBILE_HOST_REDIRECT => Type::MobileHostRedirect,
            IPV6_WHERE_ARE_YOU => Type::Ipv6WhereAreYou,
            IPV6_IAM_HERE => Type::Ipv6IAmHere,
            MOBILE_REGISTRATION_REQUEST => Type::MobileRegistrationRequest,
            MOBILE_REGISTRATION_REPLY => Type::MobileRegistrationReply,
            DOMAIN_NAME_REQUEST => Type::DomainNameRequest,
            DOMAIN_NAME_REPLY => Type::DomainNameReply,
            SKIP => Type::Skip,
            PHOTURIS => Type::Photuris,
            EXTENDED_ECHO_REQUEST => Type::ExtendedEchoRequest,
            EXTENDED_ECHO_REPLY => Type::ExtendedEchoReply,
            x => Type::Other(x),
        }
    }
}

const NO_CODE: u8 = 0;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum EchoReply {
    NoCode = NO_CODE,
    Other(u8),
}

impl AsRef<u8> for EchoReply {
    fn as_ref(&self) -> &u8 {
        match self {
            EchoReply::NoCode => &NO_CODE,
            EchoReply::Other(x) => x,
        }
    }
}

impl From<u8> for EchoReply {
    fn from(value: u8) -> Self {
        match value {
            NO_CODE => EchoReply::NoCode,
            x => EchoReply::Other(x),
        }
    }
}

impl From<EchoReply> for u8 {
    fn from(value: EchoReply) -> u8 {
        *value.as_ref()
    }
}

const NET_UNREACHABLE: u8 = 0;
const HOST_UNREACHABLE: u8 = 1;
const PROTOCOL_UNREACHABLE: u8 = 2;
const PORT_UNREACHABLE: u8 = 3;
const FRAGMENTATION_NEEDED_AND_DONT_FRAGMENT_WAS_SET: u8 = 4;
const SOURCE_ROUTE_FAILED: u8 = 5;
const DESTINATION_NETWORK_UNKNOWN: u8 = 6;
const DESTINATION_HOST_UNKNOWN: u8 = 7;
const SOURCE_HOST_ISOLATED: u8 = 8;
const COMMUNICATION_WITH_DESTINATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED:
    u8 = 9;
const COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED: u8 =
    10;
const DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE: u8 = 11;
const DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE: u8 = 12;
const COMMUNICATION_ADMINISTRATIVELY_PROHIBITED: u8 = 13;
const HOST_PRECEDENCE_VIOLATION: u8 = 14;
const PRECEDENCE_CUTOFF_IN_EFFECT: u8 = 15;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum DestinationUnreachable {
    NetUnreachable = NET_UNREACHABLE,
    HostUnreachable = HOST_UNREACHABLE,
    ProtocolUnreachable = PROTOCOL_UNREACHABLE,
    PortUnreachable = PORT_UNREACHABLE,
    FragmentationNeededAndDontFragmentWasSet =
        FRAGMENTATION_NEEDED_AND_DONT_FRAGMENT_WAS_SET,
    SourceRouteFailed = SOURCE_ROUTE_FAILED,
    DestinationNetworkUnknown = DESTINATION_NETWORK_UNKNOWN,
    DestinationHostUnknown = DESTINATION_HOST_UNKNOWN,
    SourceHostIsolated = SOURCE_HOST_ISOLATED,
    CommunicationWithDestinationNetworkIsAdministrativelyProhibited =
        COMMUNICATION_WITH_DESTINATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED,
    CommunicationWithDestinationHostIsAdministrativelyProhibited =
        COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED,
    DestinationNetworkUnreachableForTypeOfService =
        DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE,
    DestinationHostUnreachableForTypeOfService =
        DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE,
    CommunicationAdministrativelyProhibited =
        COMMUNICATION_ADMINISTRATIVELY_PROHIBITED,
    HostPrecedenceViolation = HOST_PRECEDENCE_VIOLATION,
    PrecedenceCutoffInEffect = PRECEDENCE_CUTOFF_IN_EFFECT,
    Other(u8),
}

impl AsRef<u8> for DestinationUnreachable {
    fn as_ref(&self) -> &u8 {
        match self {
            DestinationUnreachable::NetUnreachable => &NET_UNREACHABLE,
            DestinationUnreachable::HostUnreachable => &HOST_UNREACHABLE,
            DestinationUnreachable::ProtocolUnreachable => &PROTOCOL_UNREACHABLE,
            DestinationUnreachable::PortUnreachable => &PORT_UNREACHABLE,
            DestinationUnreachable::FragmentationNeededAndDontFragmentWasSet => &FRAGMENTATION_NEEDED_AND_DONT_FRAGMENT_WAS_SET,
            DestinationUnreachable::SourceRouteFailed => &SOURCE_ROUTE_FAILED,
            DestinationUnreachable::DestinationNetworkUnknown => &DESTINATION_NETWORK_UNKNOWN,
            DestinationUnreachable::DestinationHostUnknown => &DESTINATION_HOST_UNKNOWN,
            DestinationUnreachable::SourceHostIsolated => &SOURCE_HOST_ISOLATED,
            DestinationUnreachable::CommunicationWithDestinationNetworkIsAdministrativelyProhibited => &COMMUNICATION_WITH_DESTINATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED,
            DestinationUnreachable::CommunicationWithDestinationHostIsAdministrativelyProhibited => &COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED,
            DestinationUnreachable::DestinationNetworkUnreachableForTypeOfService => &DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE,
            DestinationUnreachable::DestinationHostUnreachableForTypeOfService => &DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE,
            DestinationUnreachable::CommunicationAdministrativelyProhibited => &COMMUNICATION_ADMINISTRATIVELY_PROHIBITED,
            DestinationUnreachable::HostPrecedenceViolation => &HOST_PRECEDENCE_VIOLATION,
            DestinationUnreachable::PrecedenceCutoffInEffect => &PRECEDENCE_CUTOFF_IN_EFFECT,
            DestinationUnreachable::Other(x) => x,
        }
    }
}

impl From<u8> for DestinationUnreachable {
    fn from(value: u8) -> Self {
        match value {
        NET_UNREACHABLE => DestinationUnreachable::NetUnreachable,
        HOST_UNREACHABLE => DestinationUnreachable::HostUnreachable,
        PROTOCOL_UNREACHABLE => DestinationUnreachable::ProtocolUnreachable,
        PORT_UNREACHABLE => DestinationUnreachable::PortUnreachable,
        FRAGMENTATION_NEEDED_AND_DONT_FRAGMENT_WAS_SET => DestinationUnreachable::FragmentationNeededAndDontFragmentWasSet,
        SOURCE_ROUTE_FAILED => DestinationUnreachable::SourceRouteFailed,
        DESTINATION_NETWORK_UNKNOWN => DestinationUnreachable::DestinationNetworkUnknown,
        DESTINATION_HOST_UNKNOWN => DestinationUnreachable::DestinationHostUnknown,
        SOURCE_HOST_ISOLATED => DestinationUnreachable::SourceHostIsolated,
        COMMUNICATION_WITH_DESTINATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED => DestinationUnreachable::CommunicationWithDestinationNetworkIsAdministrativelyProhibited,
        COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED => DestinationUnreachable::CommunicationWithDestinationHostIsAdministrativelyProhibited,
        DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE => DestinationUnreachable::DestinationNetworkUnreachableForTypeOfService,
        DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE => DestinationUnreachable::DestinationHostUnreachableForTypeOfService,
        COMMUNICATION_ADMINISTRATIVELY_PROHIBITED => DestinationUnreachable::CommunicationAdministrativelyProhibited,
        HOST_PRECEDENCE_VIOLATION => DestinationUnreachable::HostPrecedenceViolation,
        PRECEDENCE_CUTOFF_IN_EFFECT => DestinationUnreachable::PrecedenceCutoffInEffect,
        x => DestinationUnreachable::Other(x),
        }
    }
}

impl From<DestinationUnreachable> for u8 {
    fn from(value: DestinationUnreachable) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum SourceQuench {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for SourceQuench {
    fn as_ref(&self) -> &u8 {
        match self {
            SourceQuench::NoCode => &0,
            SourceQuench::Other(x) => x,
        }
    }
}

impl From<u8> for SourceQuench {
    fn from(value: u8) -> Self {
        match value {
            0 => SourceQuench::NoCode,
            x => SourceQuench::Other(x),
        }
    }
}

impl From<SourceQuench> for u8 {
    fn from(value: SourceQuench) -> u8 {
        *value.as_ref()
    }
}

mod redirect {
    pub(super) const NET: u8 = 0;
    pub(super) const HOST: u8 = 1;
    pub(super) const TO_SAND_NET: u8 = 2;
    pub(super) const TO_SAND_HOST: u8 = 3;
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Redirect {
    Net = redirect::NET,
    Host = redirect::HOST,
    ToSAndNet = redirect::TO_SAND_NET,
    ToSAndHost = redirect::TO_SAND_HOST,
    Other(u8),
}

impl AsRef<u8> for Redirect {
    fn as_ref(&self) -> &u8 {
        match self {
            Redirect::Net => &redirect::NET,
            Redirect::Host => &redirect::HOST,
            Redirect::ToSAndNet => &redirect::TO_SAND_NET,
            Redirect::ToSAndHost => &redirect::TO_SAND_HOST,
            Redirect::Other(x) => x,
        }
    }
}

impl From<u8> for Redirect {
    fn from(value: u8) -> Self {
        match value {
            redirect::NET => Redirect::Net,
            redirect::HOST => Redirect::Host,
            redirect::TO_SAND_NET => Redirect::ToSAndNet,
            redirect::TO_SAND_HOST => Redirect::ToSAndHost,
            x => Redirect::Other(x),
        }
    }
}

impl From<Redirect> for u8 {
    fn from(value: Redirect) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum AlternateHostAddress {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for AlternateHostAddress {
    fn as_ref(&self) -> &u8 {
        match self {
            AlternateHostAddress::NoCode => &0,
            AlternateHostAddress::Other(x) => x,
        }
    }
}

impl From<u8> for AlternateHostAddress {
    fn from(value: u8) -> Self {
        match value {
            0 => AlternateHostAddress::NoCode,
            x => AlternateHostAddress::Other(x),
        }
    }
}

impl From<AlternateHostAddress> for u8 {
    fn from(value: AlternateHostAddress) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum EchoRequest {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for EchoRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            EchoRequest::NoCode => &0,
            EchoRequest::Other(x) => x,
        }
    }
}

impl From<u8> for EchoRequest {
    fn from(value: u8) -> Self {
        match value {
            0 => EchoRequest::NoCode,
            x => EchoRequest::Other(x),
        }
    }
}

impl From<EchoRequest> for u8 {
    fn from(value: EchoRequest) -> u8 {
        *value.as_ref()
    }
}

const DOES_NOT_ROUTE_COMMON_TRAFFIC: u8 = 16;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum RouterAdvertisement {
    NoCode = 0,
    DoesNotRouteCommonTraffic = DOES_NOT_ROUTE_COMMON_TRAFFIC,
    Other(u8),
}

impl AsRef<u8> for RouterAdvertisement {
    fn as_ref(&self) -> &u8 {
        match self {
            RouterAdvertisement::NoCode => &0,
            RouterAdvertisement::DoesNotRouteCommonTraffic => {
                &DOES_NOT_ROUTE_COMMON_TRAFFIC
            }
            RouterAdvertisement::Other(x) => x,
        }
    }
}

impl From<u8> for RouterAdvertisement {
    fn from(value: u8) -> Self {
        match value {
            0 => RouterAdvertisement::NoCode,
            DOES_NOT_ROUTE_COMMON_TRAFFIC => {
                RouterAdvertisement::DoesNotRouteCommonTraffic
            }
            x => RouterAdvertisement::Other(x),
        }
    }
}

impl From<RouterAdvertisement> for u8 {
    fn from(value: RouterAdvertisement) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum RouterSolicitation {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for RouterSolicitation {
    fn as_ref(&self) -> &u8 {
        match self {
            RouterSolicitation::NoCode => &0,
            RouterSolicitation::Other(x) => x,
        }
    }
}

impl From<u8> for RouterSolicitation {
    fn from(value: u8) -> Self {
        match value {
            0 => RouterSolicitation::NoCode,
            x => RouterSolicitation::Other(x),
        }
    }
}

impl From<RouterSolicitation> for u8 {
    fn from(value: RouterSolicitation) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum TimeExceeded {
    TtlExceededInTransit = 0,
    FragmentReassembly = 1,
    Other(u8),
}

impl AsRef<u8> for TimeExceeded {
    fn as_ref(&self) -> &u8 {
        match self {
            TimeExceeded::TtlExceededInTransit => &0,
            TimeExceeded::FragmentReassembly => &1,
            TimeExceeded::Other(x) => x,
        }
    }
}

impl From<u8> for TimeExceeded {
    fn from(value: u8) -> Self {
        match value {
            0 => TimeExceeded::TtlExceededInTransit,
            1 => TimeExceeded::FragmentReassembly,
            x => TimeExceeded::Other(x),
        }
    }
}

impl From<TimeExceeded> for u8 {
    fn from(value: TimeExceeded) -> u8 {
        *value.as_ref()
    }
}

const POINTER_INDICATES_THE_ERROR: u8 = 0;
const MISSING_A_REQUIRED_OPTION: u8 = 1;
const BAD_LENGTH: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum ParameterProblem {
    PointerIndicatesTheError = POINTER_INDICATES_THE_ERROR,
    MissingARequiredOption = MISSING_A_REQUIRED_OPTION,
    BadLength = BAD_LENGTH,
    Other(u8),
}

impl AsRef<u8> for ParameterProblem {
    fn as_ref(&self) -> &u8 {
        match self {
            ParameterProblem::PointerIndicatesTheError => {
                &POINTER_INDICATES_THE_ERROR
            }
            ParameterProblem::MissingARequiredOption => {
                &MISSING_A_REQUIRED_OPTION
            }
            ParameterProblem::BadLength => &BAD_LENGTH,
            ParameterProblem::Other(x) => x,
        }
    }
}

impl From<u8> for ParameterProblem {
    fn from(value: u8) -> Self {
        match value {
            POINTER_INDICATES_THE_ERROR => {
                ParameterProblem::PointerIndicatesTheError
            }
            MISSING_A_REQUIRED_OPTION => {
                ParameterProblem::MissingARequiredOption
            }
            BAD_LENGTH => ParameterProblem::BadLength,
            x => ParameterProblem::Other(x),
        }
    }
}

impl From<ParameterProblem> for u8 {
    fn from(value: ParameterProblem) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum TimestampRequest {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for TimestampRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            TimestampRequest::NoCode => &0,
            TimestampRequest::Other(x) => x,
        }
    }
}

impl From<u8> for TimestampRequest {
    fn from(value: u8) -> Self {
        match value {
            0 => TimestampRequest::NoCode,
            x => TimestampRequest::Other(x),
        }
    }
}

impl From<TimestampRequest> for u8 {
    fn from(value: TimestampRequest) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum TimestampReply {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for TimestampReply {
    fn as_ref(&self) -> &u8 {
        match self {
            TimestampReply::NoCode => &0,
            TimestampReply::Other(x) => x,
        }
    }
}

impl From<u8> for TimestampReply {
    fn from(value: u8) -> Self {
        match value {
            0 => TimestampReply::NoCode,
            x => TimestampReply::Other(x),
        }
    }
}

impl From<TimestampReply> for u8 {
    fn from(value: TimestampReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum InformationRequest {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for InformationRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            InformationRequest::NoCode => &0,
            InformationRequest::Other(x) => x,
        }
    }
}

impl From<u8> for InformationRequest {
    fn from(value: u8) -> Self {
        match value {
            0 => InformationRequest::NoCode,
            x => InformationRequest::Other(x),
        }
    }
}

impl From<InformationRequest> for u8 {
    fn from(value: InformationRequest) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum InformationReply {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for InformationReply {
    fn as_ref(&self) -> &u8 {
        match self {
            InformationReply::NoCode => &0,
            InformationReply::Other(x) => x,
        }
    }
}

impl From<u8> for InformationReply {
    fn from(value: u8) -> Self {
        match value {
            0 => InformationReply::NoCode,
            x => InformationReply::Other(x),
        }
    }
}

impl From<InformationReply> for u8 {
    fn from(value: InformationReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum AddressMaskRequest {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for AddressMaskRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            AddressMaskRequest::NoCode => &0,
            AddressMaskRequest::Other(x) => x,
        }
    }
}

impl From<u8> for AddressMaskRequest {
    fn from(value: u8) -> Self {
        match value {
            0 => AddressMaskRequest::NoCode,
            x => AddressMaskRequest::Other(x),
        }
    }
}

impl From<AddressMaskRequest> for u8 {
    fn from(value: AddressMaskRequest) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum AddressMaskReply {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for AddressMaskReply {
    fn as_ref(&self) -> &u8 {
        match self {
            AddressMaskReply::NoCode => &0,
            AddressMaskReply::Other(x) => x,
        }
    }
}

impl From<u8> for AddressMaskReply {
    fn from(value: u8) -> Self {
        match value {
            0 => AddressMaskReply::NoCode,
            x => AddressMaskReply::Other(x),
        }
    }
}

impl From<AddressMaskReply> for u8 {
    fn from(value: AddressMaskReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Traceroute {
    NoCode = 0,
    Other(u8),
}

impl AsRef<u8> for Traceroute {
    fn as_ref(&self) -> &u8 {
        match self {
            Traceroute::NoCode => &0,
            Traceroute::Other(x) => x,
        }
    }
}

impl From<u8> for Traceroute {
    fn from(value: u8) -> Self {
        match value {
            0 => Traceroute::NoCode,
            x => Traceroute::Other(x),
        }
    }
}

impl From<Traceroute> for u8 {
    fn from(value: Traceroute) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum DatagramConversionError {
    Other(u8),
}

impl AsRef<u8> for DatagramConversionError {
    fn as_ref(&self) -> &u8 {
        match self {
            DatagramConversionError::Other(x) => x,
        }
    }
}

impl From<u8> for DatagramConversionError {
    fn from(value: u8) -> Self {
        DatagramConversionError::Other(value)
    }
}

impl From<DatagramConversionError> for u8 {
    fn from(value: DatagramConversionError) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum MobileHostRedirect {
    Other(u8),
}

impl AsRef<u8> for MobileHostRedirect {
    fn as_ref(&self) -> &u8 {
        match self {
            MobileHostRedirect::Other(x) => x,
        }
    }
}

impl From<u8> for MobileHostRedirect {
    fn from(value: u8) -> Self {
        MobileHostRedirect::Other(value)
    }
}

impl From<MobileHostRedirect> for u8 {
    fn from(value: MobileHostRedirect) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Ipv6WhereAreYou {
    Other(u8),
}

impl AsRef<u8> for Ipv6WhereAreYou {
    fn as_ref(&self) -> &u8 {
        match self {
            Ipv6WhereAreYou::Other(x) => x,
        }
    }
}

impl From<u8> for Ipv6WhereAreYou {
    fn from(value: u8) -> Self {
        Ipv6WhereAreYou::Other(value)
    }
}

impl From<Ipv6WhereAreYou> for u8 {
    fn from(value: Ipv6WhereAreYou) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Ipv6IAmHere {
    Other(u8),
}

impl AsRef<u8> for Ipv6IAmHere {
    fn as_ref(&self) -> &u8 {
        match self {
            Ipv6IAmHere::Other(x) => x,
        }
    }
}

impl From<u8> for Ipv6IAmHere {
    fn from(value: u8) -> Self {
        Ipv6IAmHere::Other(value)
    }
}

impl From<Ipv6IAmHere> for u8 {
    fn from(value: Ipv6IAmHere) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum MobileRegistrationRequest {
    Other(u8),
}

impl AsRef<u8> for MobileRegistrationRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            MobileRegistrationRequest::Other(x) => x,
        }
    }
}

impl From<u8> for MobileRegistrationRequest {
    fn from(value: u8) -> Self {
        MobileRegistrationRequest::Other(value)
    }
}

impl From<MobileRegistrationRequest> for u8 {
    fn from(value: MobileRegistrationRequest) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum MobileRegistrationReply {
    Other(u8),
}

impl AsRef<u8> for MobileRegistrationReply {
    fn as_ref(&self) -> &u8 {
        match self {
            MobileRegistrationReply::Other(x) => x,
        }
    }
}

impl From<u8> for MobileRegistrationReply {
    fn from(value: u8) -> Self {
        MobileRegistrationReply::Other(value)
    }
}

impl From<MobileRegistrationReply> for u8 {
    fn from(value: MobileRegistrationReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum DomainNameRequest {
    Other(u8),
}

impl AsRef<u8> for DomainNameRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            DomainNameRequest::Other(x) => x,
        }
    }
}

impl From<u8> for DomainNameRequest {
    fn from(value: u8) -> Self {
        DomainNameRequest::Other(value)
    }
}

impl From<DomainNameRequest> for u8 {
    fn from(value: DomainNameRequest) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum DomainNameReply {
    Other(u8),
}

impl AsRef<u8> for DomainNameReply {
    fn as_ref(&self) -> &u8 {
        match self {
            DomainNameReply::Other(x) => x,
        }
    }
}

impl From<u8> for DomainNameReply {
    fn from(value: u8) -> Self {
        DomainNameReply::Other(value)
    }
}

impl From<DomainNameReply> for u8 {
    fn from(value: DomainNameReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Skip {
    Other(u8),
}

impl AsRef<u8> for Skip {
    fn as_ref(&self) -> &u8 {
        match self {
            Skip::Other(x) => x,
        }
    }
}

impl From<u8> for Skip {
    fn from(value: u8) -> Self {
        Skip::Other(value)
    }
}

impl From<Skip> for u8 {
    fn from(value: Skip) -> u8 {
        *value.as_ref()
    }
}

const BAD_SPI: u8 = 0;
const AUTHENTICATION_FAILED: u8 = 1;
const DECOMPRESSION_FAILED: u8 = 2;
const DECRYPTION_FAILED: u8 = 3;
const NEED_AUTHENTICATION: u8 = 4;
const NEED_AUTHORIZATION: u8 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Photuris {
    BadSpi = BAD_SPI,
    AuthenticationFailed = AUTHENTICATION_FAILED,
    DecompressionFailed = DECOMPRESSION_FAILED,
    DecryptionFailed = DECRYPTION_FAILED,
    NeedAuthentication = NEED_AUTHENTICATION,
    NeedAuthorization = NEED_AUTHORIZATION,
    Other(u8),
}

impl AsRef<u8> for Photuris {
    fn as_ref(&self) -> &u8 {
        match self {
            Photuris::BadSpi => &BAD_SPI,
            Photuris::AuthenticationFailed => &AUTHENTICATION_FAILED,
            Photuris::DecompressionFailed => &DECOMPRESSION_FAILED,
            Photuris::DecryptionFailed => &DECRYPTION_FAILED,
            Photuris::NeedAuthentication => &NEED_AUTHENTICATION,
            Photuris::NeedAuthorization => &NEED_AUTHORIZATION,
            Photuris::Other(x) => x,
        }
    }
}

impl From<u8> for Photuris {
    fn from(value: u8) -> Self {
        match value {
            BAD_SPI => Photuris::BadSpi,
            AUTHENTICATION_FAILED => Photuris::AuthenticationFailed,
            DECOMPRESSION_FAILED => Photuris::DecompressionFailed,
            DECRYPTION_FAILED => Photuris::DecryptionFailed,
            NEED_AUTHENTICATION => Photuris::NeedAuthentication,
            NEED_AUTHORIZATION => Photuris::NeedAuthorization,
            x => Photuris::Other(x),
        }
    }
}

impl From<Photuris> for u8 {
    fn from(value: Photuris) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum ExtendedEchoRequest {
    NoError = 0,
    Other(u8),
}

impl AsRef<u8> for ExtendedEchoRequest {
    fn as_ref(&self) -> &u8 {
        match self {
            ExtendedEchoRequest::NoError => &0,
            ExtendedEchoRequest::Other(x) => x,
        }
    }
}

impl From<u8> for ExtendedEchoRequest {
    fn from(value: u8) -> Self {
        match value {
            0 => ExtendedEchoRequest::NoError,
            x => ExtendedEchoRequest::Other(x),
        }
    }
}

impl From<ExtendedEchoRequest> for u8 {
    fn from(value: ExtendedEchoRequest) -> u8 {
        *value.as_ref()
    }
}

const NO_ERROR: u8 = 0;
const MALFORMED_QUERY: u8 = 1;
const NO_SUCH_INTERFACE: u8 = 2;
const NO_SUCH_TABLE_ENTRY: u8 = 3;
const MULTIPLE_INTERFACES_SATISFY_QUERY: u8 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum ExtendedEchoReply {
    NoError = NO_ERROR,
    MalformedQuery = MALFORMED_QUERY,
    NoSuchInterface = NO_SUCH_INTERFACE,
    NoSuchTableEntry = NO_SUCH_TABLE_ENTRY,
    MultipleInterfacesSatisfyQuery = MULTIPLE_INTERFACES_SATISFY_QUERY,
    Other(u8),
}

impl AsRef<u8> for ExtendedEchoReply {
    fn as_ref(&self) -> &u8 {
        match self {
            ExtendedEchoReply::NoError => &NO_ERROR,
            ExtendedEchoReply::MalformedQuery => &MALFORMED_QUERY,
            ExtendedEchoReply::NoSuchInterface => &NO_SUCH_INTERFACE,
            ExtendedEchoReply::NoSuchTableEntry => &NO_SUCH_TABLE_ENTRY,
            ExtendedEchoReply::MultipleInterfacesSatisfyQuery => {
                &MULTIPLE_INTERFACES_SATISFY_QUERY
            }
            ExtendedEchoReply::Other(x) => x,
        }
    }
}

impl From<u8> for ExtendedEchoReply {
    fn from(value: u8) -> Self {
        match value {
            NO_ERROR => ExtendedEchoReply::NoError,
            MALFORMED_QUERY => ExtendedEchoReply::MalformedQuery,
            NO_SUCH_INTERFACE => ExtendedEchoReply::NoSuchInterface,
            NO_SUCH_TABLE_ENTRY => ExtendedEchoReply::NoSuchTableEntry,
            MULTIPLE_INTERFACES_SATISFY_QUERY => {
                ExtendedEchoReply::MultipleInterfacesSatisfyQuery
            }
            x => ExtendedEchoReply::Other(x),
        }
    }
}

impl From<ExtendedEchoReply> for u8 {
    fn from(value: ExtendedEchoReply) -> u8 {
        *value.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u8)]
pub enum Code {
    EchoReply(EchoReply),
    DestinationUnreachable(DestinationUnreachable),
    SourceQuench(SourceQuench),
    Redirect(Redirect),
    AlternateHostAddress(AlternateHostAddress),
    EchoRequest(EchoRequest),
    RouterAdvertisement(RouterAdvertisement),
    RouterSolicitation(RouterSolicitation),
    TimeExceeded(TimeExceeded),
    ParameterProblem(ParameterProblem),
    TimestampRequest(TimestampRequest),
    TimestampReply(TimestampReply),
    InformationRequest(InformationRequest),
    InformationReply(InformationReply),
    AddressMaskRequest(AddressMaskRequest),
    AddressMaskReply(AddressMaskReply),
    Traceroute(Traceroute),
    DatagramConversionError(DatagramConversionError),
    MobileHostRedirect(MobileHostRedirect),
    Ipv6WhereAreYou(Ipv6WhereAreYou),
    Ipv6IAmHere(Ipv6IAmHere),
    MobileRegistrationRequest(MobileRegistrationRequest),
    MobileRegistrationReply(MobileRegistrationReply),
    DomainNameRequest(DomainNameRequest),
    DomainNameReply(DomainNameReply),
    Skip(Skip),
    Photuris(Photuris),
    ExtendedEchoRequest(ExtendedEchoRequest),
    ExtendedEchoReply(ExtendedEchoReply),
    Other(u8),
}

impl AsRef<u8> for Code {
    fn as_ref(&self) -> &u8 {
        match self {
            Code::EchoReply(x) => x.as_ref(),
            Code::DestinationUnreachable(x) => x.as_ref(),
            Code::SourceQuench(x) => x.as_ref(),
            Code::Redirect(x) => x.as_ref(),
            Code::AlternateHostAddress(x) => x.as_ref(),
            Code::EchoRequest(x) => x.as_ref(),
            Code::RouterAdvertisement(x) => x.as_ref(),
            Code::RouterSolicitation(x) => x.as_ref(),
            Code::TimeExceeded(x) => x.as_ref(),
            Code::ParameterProblem(x) => x.as_ref(),
            Code::TimestampRequest(x) => x.as_ref(),
            Code::TimestampReply(x) => x.as_ref(),
            Code::InformationRequest(x) => x.as_ref(),
            Code::InformationReply(x) => x.as_ref(),
            Code::AddressMaskRequest(x) => x.as_ref(),
            Code::AddressMaskReply(x) => x.as_ref(),
            Code::Traceroute(x) => x.as_ref(),
            Code::DatagramConversionError(x) => x.as_ref(),
            Code::MobileHostRedirect(x) => x.as_ref(),
            Code::Ipv6WhereAreYou(x) => x.as_ref(),
            Code::Ipv6IAmHere(x) => x.as_ref(),
            Code::MobileRegistrationRequest(x) => x.as_ref(),
            Code::MobileRegistrationReply(x) => x.as_ref(),
            Code::DomainNameRequest(x) => x.as_ref(),
            Code::DomainNameReply(x) => x.as_ref(),
            Code::Skip(x) => x.as_ref(),
            Code::Photuris(x) => x.as_ref(),
            Code::ExtendedEchoRequest(x) => x.as_ref(),
            Code::ExtendedEchoReply(x) => x.as_ref(),
            Code::Other(x) => x,
        }
    }
}
