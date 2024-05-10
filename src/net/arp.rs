const RESERVED: u8 = 0;
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const REQUEST_REVERSE: u8 = 3;
const REPLY_REVERSE: u8 = 4;
const DRARP_REQUEST: u8 = 5;
const DRARP_REPLY: u8 = 6;
const DRARP_ERROR: u8 = 7;
const IN_ARP_REQUEST: u8 = 8;
const IN_ARP_REPLY: u8 = 9;
const ARP_NAK: u8 = 10;
const MARS_REQUEST: u8 = 11;
const MARS_MULTI: u8 = 12;
const MARS_MSERV: u8 = 13;
const MARS_JOIN: u8 = 14;
const MARS_LEAVE: u8 = 15;
const MARS_NAK: u8 = 16;
const MARS_UNSERV: u8 = 17;
const MARS_SJOIN: u8 = 18;
const MARS_SLEAVE: u8 = 19;
const MARS_GROUP_LIST_REQUEST: u8 = 20;
const MARS_GROUP_LIST_REPLY: u8 = 21;
const MARS_REDIRECT_MAP: u8 = 22;
const MAPO_SUNARP: u8 = 23;
const OP_EXP1: u8 = 24;
const OP_EXP2: u8 = 25;

/// Enum of ARP operation codes.
/// 
/// List from [iana.org][1]
/// 
/// [1]: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Operation {
    Reserved = RESERVED,
    Request = REQUEST,
    Reply = REPLY,
    RequestReverse = REQUEST_REVERSE,
    ReplyReverse = REPLY_REVERSE,
    DrarpRequest = DRARP_REQUEST,
    DrarpReply = DRARP_REPLY,
    DrarpError = DRARP_ERROR,
    InArpRequest = IN_ARP_REQUEST,
    InArpReply = IN_ARP_REPLY,
    ArpNak = ARP_NAK,
    MarsRequest = MARS_REQUEST,
    MarsMulti = MARS_MULTI,
    MarsMServ = MARS_MSERV,
    MarsJoin = MARS_JOIN,
    MarsLeave = MARS_LEAVE,
    MarsNAK = MARS_NAK,
    MarsUnserv = MARS_UNSERV,
    MarsSJoin = MARS_SJOIN,
    MarsSLeave = MARS_SLEAVE,
    MarsGroupListRequest = MARS_GROUP_LIST_REQUEST,
    MarsGroupListReply = MARS_GROUP_LIST_REPLY,
    MarsRedirectMap = MARS_REDIRECT_MAP,
    MapoSUnarp = MAPO_SUNARP,
    OpExp1 = OP_EXP1,
    OpExp2 = OP_EXP2,
    Other(u8),
}

impl AsRef<u8> for Operation {
    fn as_ref(&self) -> &u8 {
        match self {
            Operation::Reserved => &RESERVED,
            Operation::Request => &REQUEST,
            Operation::Reply => &REPLY,
            Operation::RequestReverse => &REQUEST_REVERSE,
            Operation::ReplyReverse => &REPLY_REVERSE,
            Operation::DrarpRequest => &DRARP_REQUEST,
            Operation::DrarpReply => &DRARP_REPLY,
            Operation::DrarpError => &DRARP_ERROR,
            Operation::InArpRequest => &IN_ARP_REQUEST,
            Operation::InArpReply => &IN_ARP_REPLY,
            Operation::ArpNak => &ARP_NAK,
            Operation::MarsRequest => &MARS_REQUEST,
            Operation::MarsMulti => &MARS_MULTI,
            Operation::MarsMServ => &MARS_MSERV,
            Operation::MarsJoin => &MARS_JOIN,
            Operation::MarsLeave => &MARS_LEAVE,
            Operation::MarsNAK => &MARS_NAK,
            Operation::MarsUnserv => &MARS_UNSERV,
            Operation::MarsSJoin => &MARS_SJOIN,
            Operation::MarsSLeave => &MARS_SLEAVE,
            Operation::MarsGroupListRequest => &MARS_GROUP_LIST_REQUEST,
            Operation::MarsGroupListReply => &MARS_GROUP_LIST_REPLY,
            Operation::MarsRedirectMap => &MARS_REDIRECT_MAP,
            Operation::MapoSUnarp => &MAPO_SUNARP,
            Operation::OpExp1 => &OP_EXP1,
            Operation::OpExp2 => &OP_EXP2,
            Operation::Other(x) => x,
        }
    }
}

impl From<u8> for Operation {
    fn from(value: u8) -> Self {
        match value {
            RESERVED => Operation::Reserved,
            REQUEST => Operation::Request,
            REPLY => Operation::Reply,
            REQUEST_REVERSE => Operation::RequestReverse,
            REPLY_REVERSE => Operation::ReplyReverse,
            DRARP_REQUEST => Operation::DrarpRequest,
            DRARP_REPLY => Operation::DrarpReply,
            DRARP_ERROR => Operation::DrarpError,
            IN_ARP_REQUEST => Operation::InArpRequest,
            IN_ARP_REPLY => Operation::InArpReply,
            ARP_NAK => Operation::ArpNak,
            MARS_REQUEST => Operation::MarsRequest,
            MARS_MULTI => Operation::MarsMulti,
            MARS_MSERV => Operation::MarsMServ,
            MARS_JOIN => Operation::MarsJoin,
            MARS_LEAVE => Operation::MarsLeave,
            MARS_NAK => Operation::MarsNAK,
            MARS_UNSERV => Operation::MarsUnserv,
            MARS_SJOIN => Operation::MarsSJoin,
            MARS_SLEAVE => Operation::MarsSLeave,
            MARS_GROUP_LIST_REQUEST => Operation::MarsGroupListRequest,
            MARS_GROUP_LIST_REPLY => Operation::MarsGroupListReply,
            MARS_REDIRECT_MAP => Operation::MarsRedirectMap,
            MAPO_SUNARP => Operation::MapoSUnarp,
            OP_EXP1 => Operation::OpExp1,
            OP_EXP2 => Operation::OpExp2,
            x => Operation::Other(x),
        }
    }
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        *value.as_ref()
    }
}
