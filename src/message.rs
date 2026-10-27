// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, NetlinkDeserializable, NetlinkHeader,
    NetlinkPayload, NetlinkSerializable, ParseableParametrized,
};
#[cfg(has_message_family)]
use netlink_packet_core::{ErrorContext, Parseable};

#[cfg(feature = "address")]
use crate::address::{AddressHeader, AddressMessage};
#[cfg(feature = "addrlabel")]
use crate::addrlabel::AddrLabelMessage;
#[cfg(feature = "link")]
use crate::link::LinkMessage;
#[cfg(feature = "neighbour")]
use crate::neighbour::NeighbourMessage;
#[cfg(feature = "neighbour-table")]
use crate::neighbour_table::NeighbourTableMessage;
#[cfg(feature = "nsid")]
use crate::nsid::NsidMessage;
#[cfg(feature = "prefix")]
use crate::prefix::PrefixMessage;
#[cfg(feature = "route")]
use crate::route::{RouteHeader, RouteMessage};
#[cfg(feature = "rule")]
use crate::rule::RuleMessage;
#[cfg(feature = "stats")]
use crate::stats::StatsMessage;
#[cfg(feature = "tc")]
use crate::tc::{TcActionMessage, TcMessage};

#[cfg(feature = "link")]
const RTM_NEWLINK: u16 = 16;
#[cfg(feature = "link")]
const RTM_DELLINK: u16 = 17;
#[cfg(feature = "link")]
const RTM_GETLINK: u16 = 18;
#[cfg(feature = "link")]
const RTM_SETLINK: u16 = 19;
#[cfg(feature = "address")]
const RTM_NEWADDR: u16 = 20;
#[cfg(feature = "address")]
const RTM_DELADDR: u16 = 21;
#[cfg(feature = "address")]
const RTM_GETADDR: u16 = 22;
#[cfg(feature = "route")]
const RTM_NEWROUTE: u16 = 24;
#[cfg(feature = "route")]
const RTM_DELROUTE: u16 = 25;
#[cfg(feature = "route")]
const RTM_GETROUTE: u16 = 26;
#[cfg(feature = "neighbour")]
const RTM_NEWNEIGH: u16 = 28;
#[cfg(feature = "neighbour")]
const RTM_DELNEIGH: u16 = 29;
#[cfg(feature = "neighbour")]
const RTM_GETNEIGH: u16 = 30;
#[cfg(feature = "rule")]
const RTM_NEWRULE: u16 = 32;
#[cfg(feature = "rule")]
const RTM_DELRULE: u16 = 33;
#[cfg(feature = "rule")]
const RTM_GETRULE: u16 = 34;
#[cfg(feature = "tc")]
const RTM_NEWQDISC: u16 = 36;
#[cfg(feature = "tc")]
const RTM_DELQDISC: u16 = 37;
#[cfg(feature = "tc")]
const RTM_GETQDISC: u16 = 38;
#[cfg(feature = "tc")]
const RTM_NEWTCLASS: u16 = 40;
#[cfg(feature = "tc")]
const RTM_DELTCLASS: u16 = 41;
#[cfg(feature = "tc")]
const RTM_GETTCLASS: u16 = 42;
#[cfg(feature = "tc")]
const RTM_NEWTFILTER: u16 = 44;
#[cfg(feature = "tc")]
const RTM_DELTFILTER: u16 = 45;
#[cfg(feature = "tc")]
const RTM_GETTFILTER: u16 = 46;
#[cfg(feature = "tc")]
const RTM_NEWACTION: u16 = 48;
#[cfg(feature = "tc")]
const RTM_DELACTION: u16 = 49;
#[cfg(feature = "tc")]
const RTM_GETACTION: u16 = 50;
#[cfg(feature = "prefix")]
const RTM_NEWPREFIX: u16 = 52;
// const RTM_GETMULTICAST: u16 = 58;
// const RTM_GETANYCAST: u16 = 62;
#[cfg(feature = "neighbour-table")]
const RTM_NEWNEIGHTBL: u16 = 64;
#[cfg(feature = "neighbour-table")]
const RTM_GETNEIGHTBL: u16 = 66;
#[cfg(feature = "neighbour-table")]
const RTM_SETNEIGHTBL: u16 = 67;
// const RTM_NEWNDUSEROPT: u16 = 68;
#[cfg(feature = "addrlabel")]
const RTM_NEWADDRLABEL: u16 = 72;
#[cfg(feature = "addrlabel")]
const RTM_DELADDRLABEL: u16 = 73;
#[cfg(feature = "addrlabel")]
const RTM_GETADDRLABEL: u16 = 74;
// const RTM_GETDCB: u16 = 78;
// const RTM_SETDCB: u16 = 79;
// const RTM_NEWNETCONF: u16 = 80;
// const RTM_DELNETCONF: u16 = 81;
// const RTM_GETNETCONF: u16 = 82;
// const RTM_NEWMDB: u16 = 84;
// const RTM_DELMDB: u16 = 85;
// const RTM_GETMDB: u16 = 86;
#[cfg(feature = "nsid")]
const RTM_NEWNSID: u16 = 88;
#[cfg(feature = "nsid")]
const RTM_DELNSID: u16 = 89;
#[cfg(feature = "nsid")]
const RTM_GETNSID: u16 = 90;
#[cfg(feature = "stats")]
const RTM_NEWSTATS: u16 = 92;
#[cfg(feature = "stats")]
const RTM_GETSTATS: u16 = 94;
// const RTM_NEWCACHEREPORT: u16 = 96;
#[cfg(feature = "tc")]
const RTM_NEWCHAIN: u16 = 100;
#[cfg(feature = "tc")]
const RTM_DELCHAIN: u16 = 101;
#[cfg(feature = "tc")]
const RTM_GETCHAIN: u16 = 102;
#[cfg(feature = "link")]
const RTM_NEWLINKPROP: u16 = 108;
#[cfg(feature = "link")]
const RTM_DELLINKPROP: u16 = 109;

impl ParseableParametrized<[u8], u16> for RouteNetlinkMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let _ = buf; // No message families need the payload when all are disabled.
        match message_type {
            // Link messages
            #[cfg(feature = "link")]
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => Ok({
                // HACK: iproute2 sends invalid RTM_GETLINK message, where
                // the header is limited to the interface family (1 byte) and
                // 3 bytes of padding.
                let msg = if buf.len() == 4 && message_type == RTM_GETLINK {
                    let mut msg = LinkMessage::default();
                    msg.header.interface_family = buf[0].into();
                    msg
                } else {
                    LinkMessage::parse(buf).context("invalid link message")?
                };
                match message_type {
                    RTM_NEWLINK => RouteNetlinkMessage::NewLink(msg),
                    RTM_GETLINK => RouteNetlinkMessage::GetLink(msg),
                    RTM_DELLINK => RouteNetlinkMessage::DelLink(msg),
                    RTM_SETLINK => RouteNetlinkMessage::SetLink(msg),
                    _ => unreachable!(),
                }
            }),

            // Address messages
            #[cfg(feature = "address")]
            RTM_NEWADDR | RTM_GETADDR | RTM_DELADDR => Ok({
                // HACK: iproute2 sends invalid RTM_GETADDR message, where
                // the header is limited to the interface family (1 byte) and
                // 3 bytes of padding.
                let msg = if buf.len() == 4 && message_type == RTM_GETADDR {
                    let mut msg = AddressMessage {
                        header: AddressHeader::default(),
                        attributes: vec![],
                    };
                    msg.header.family = buf[0].into();
                    msg
                } else {
                    AddressMessage::parse(buf)
                        .context("invalid address message")?
                };
                match message_type {
                    RTM_NEWADDR => RouteNetlinkMessage::NewAddress(msg),
                    RTM_GETADDR => RouteNetlinkMessage::GetAddress(msg),
                    RTM_DELADDR => RouteNetlinkMessage::DelAddress(msg),
                    _ => unreachable!(),
                }
            }),

            // Neighbour messages
            #[cfg(feature = "neighbour")]
            RTM_NEWNEIGH | RTM_GETNEIGH | RTM_DELNEIGH => Ok({
                let err = "invalid neighbour message";
                let msg = NeighbourMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_GETNEIGH => RouteNetlinkMessage::GetNeighbour(msg),
                    RTM_NEWNEIGH => RouteNetlinkMessage::NewNeighbour(msg),
                    RTM_DELNEIGH => RouteNetlinkMessage::DelNeighbour(msg),
                    _ => unreachable!(),
                }
            }),

            // Address label messages
            #[cfg(feature = "addrlabel")]
            RTM_NEWADDRLABEL | RTM_DELADDRLABEL | RTM_GETADDRLABEL => Ok({
                let err = "invalid addrlabel message";
                let msg = AddrLabelMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWADDRLABEL => RouteNetlinkMessage::NewAddrLabel(msg),
                    RTM_DELADDRLABEL => RouteNetlinkMessage::DelAddrLabel(msg),
                    RTM_GETADDRLABEL => RouteNetlinkMessage::GetAddrLabel(msg),
                    _ => unreachable!(),
                }
            }),

            // Neighbour table messages
            #[cfg(feature = "neighbour-table")]
            RTM_NEWNEIGHTBL | RTM_GETNEIGHTBL | RTM_SETNEIGHTBL => Ok({
                let err = "invalid neighbour table message";
                let msg = NeighbourTableMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_GETNEIGHTBL => {
                        RouteNetlinkMessage::GetNeighbourTable(msg)
                    }
                    RTM_NEWNEIGHTBL => {
                        RouteNetlinkMessage::NewNeighbourTable(msg)
                    }
                    RTM_SETNEIGHTBL => {
                        RouteNetlinkMessage::SetNeighbourTable(msg)
                    }
                    _ => unreachable!(),
                }
            }),

            // Route messages
            #[cfg(feature = "route")]
            RTM_NEWROUTE | RTM_GETROUTE | RTM_DELROUTE => Ok({
                // HACK: iproute2 sends invalid RTM_GETROUTE message, where
                // the header is limited to the interface family (1 byte) and
                // 3 bytes of padding.
                //
                // Not only does iproute2 sends invalid messages, it's also
                // inconsistent in doing so: for link and address messages, the
                // length advertised in the netlink header includes the 3 bytes
                // of padding but it does not seem to be the case for the route
                // message, hence the buf.length() == 1 check.
                let msg = if (buf.len() == 4 || buf.len() == 1)
                    && message_type == RTM_GETROUTE
                {
                    let mut msg = RouteMessage {
                        header: RouteHeader::default(),
                        attributes: vec![],
                    };
                    msg.header.address_family = buf[0].into();
                    msg
                } else {
                    RouteMessage::parse(buf).context("invalid route message")?
                };
                match message_type {
                    RTM_NEWROUTE => RouteNetlinkMessage::NewRoute(msg),
                    RTM_GETROUTE => RouteNetlinkMessage::GetRoute(msg),
                    RTM_DELROUTE => RouteNetlinkMessage::DelRoute(msg),
                    _ => unreachable!(),
                }
            }),

            // Prefix messages
            #[cfg(feature = "prefix")]
            RTM_NEWPREFIX => Ok({
                let err = "invalid prefix message";
                RouteNetlinkMessage::NewPrefix(
                    PrefixMessage::parse(buf).context(err)?,
                )
            }),

            #[cfg(feature = "rule")]
            RTM_NEWRULE | RTM_GETRULE | RTM_DELRULE => Ok({
                let err = "invalid fib rule message";
                let msg = RuleMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWRULE => RouteNetlinkMessage::NewRule(msg),
                    RTM_DELRULE => RouteNetlinkMessage::DelRule(msg),
                    RTM_GETRULE => RouteNetlinkMessage::GetRule(msg),
                    _ => unreachable!(),
                }
            }),
            // TC Messages
            #[cfg(feature = "tc")]
            RTM_NEWQDISC | RTM_DELQDISC | RTM_GETQDISC | RTM_NEWTCLASS
            | RTM_DELTCLASS | RTM_GETTCLASS | RTM_NEWTFILTER
            | RTM_DELTFILTER | RTM_GETTFILTER | RTM_NEWCHAIN | RTM_DELCHAIN
            | RTM_GETCHAIN => Ok({
                let err = "invalid tc message";
                let msg = TcMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWQDISC => {
                        RouteNetlinkMessage::NewQueueDiscipline(msg)
                    }
                    RTM_DELQDISC => {
                        RouteNetlinkMessage::DelQueueDiscipline(msg)
                    }
                    RTM_GETQDISC => {
                        RouteNetlinkMessage::GetQueueDiscipline(msg)
                    }
                    RTM_NEWTCLASS => RouteNetlinkMessage::NewTrafficClass(msg),
                    RTM_DELTCLASS => RouteNetlinkMessage::DelTrafficClass(msg),
                    RTM_GETTCLASS => RouteNetlinkMessage::GetTrafficClass(msg),
                    RTM_NEWTFILTER => {
                        RouteNetlinkMessage::NewTrafficFilter(msg)
                    }
                    RTM_DELTFILTER => {
                        RouteNetlinkMessage::DelTrafficFilter(msg)
                    }
                    RTM_GETTFILTER => {
                        RouteNetlinkMessage::GetTrafficFilter(msg)
                    }
                    RTM_NEWCHAIN => RouteNetlinkMessage::NewTrafficChain(msg),
                    RTM_DELCHAIN => RouteNetlinkMessage::DelTrafficChain(msg),
                    RTM_GETCHAIN => RouteNetlinkMessage::GetTrafficChain(msg),
                    _ => unreachable!(),
                }
            }),

            #[cfg(feature = "tc")]
            RTM_NEWACTION | RTM_DELACTION | RTM_GETACTION => Ok({
                let err = "invalid tc action message";
                let msg = TcActionMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWACTION => RouteNetlinkMessage::NewTrafficAction(msg),
                    RTM_DELACTION => RouteNetlinkMessage::DelTrafficAction(msg),
                    RTM_GETACTION => RouteNetlinkMessage::GetTrafficAction(msg),
                    _ => unreachable!(),
                }
            }),

            // Stats messages
            #[cfg(feature = "stats")]
            RTM_NEWSTATS | RTM_GETSTATS => Ok({
                let err = "invalid stats message";
                let msg = StatsMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWSTATS => RouteNetlinkMessage::NewStats(msg),
                    RTM_GETSTATS => RouteNetlinkMessage::GetStats(msg),
                    _ => unreachable!(),
                }
            }),

            // ND ID Messages
            #[cfg(feature = "nsid")]
            RTM_NEWNSID | RTM_GETNSID | RTM_DELNSID => Ok({
                let err = "invalid nsid message";
                let msg = NsidMessage::parse(buf).context(err)?;
                match message_type {
                    RTM_NEWNSID => RouteNetlinkMessage::NewNsId(msg),
                    RTM_DELNSID => RouteNetlinkMessage::DelNsId(msg),
                    RTM_GETNSID => RouteNetlinkMessage::GetNsId(msg),
                    _ => unreachable!(),
                }
            }),

            _ => Err(format!("Unknown message type: {message_type}").into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteNetlinkMessage {
    #[cfg(feature = "link")]
    NewLink(LinkMessage),
    #[cfg(feature = "link")]
    DelLink(LinkMessage),
    #[cfg(feature = "link")]
    GetLink(LinkMessage),
    #[cfg(feature = "link")]
    SetLink(LinkMessage),
    #[cfg(feature = "link")]
    NewLinkProp(LinkMessage),
    #[cfg(feature = "link")]
    DelLinkProp(LinkMessage),
    #[cfg(feature = "address")]
    NewAddress(AddressMessage),
    #[cfg(feature = "address")]
    DelAddress(AddressMessage),
    #[cfg(feature = "address")]
    GetAddress(AddressMessage),
    #[cfg(feature = "addrlabel")]
    NewAddrLabel(AddrLabelMessage),
    #[cfg(feature = "addrlabel")]
    DelAddrLabel(AddrLabelMessage),
    #[cfg(feature = "addrlabel")]
    GetAddrLabel(AddrLabelMessage),
    #[cfg(feature = "neighbour")]
    NewNeighbour(NeighbourMessage),
    #[cfg(feature = "neighbour")]
    GetNeighbour(NeighbourMessage),
    #[cfg(feature = "neighbour")]
    DelNeighbour(NeighbourMessage),
    #[cfg(feature = "neighbour-table")]
    NewNeighbourTable(NeighbourTableMessage),
    #[cfg(feature = "neighbour-table")]
    GetNeighbourTable(NeighbourTableMessage),
    #[cfg(feature = "neighbour-table")]
    SetNeighbourTable(NeighbourTableMessage),
    #[cfg(feature = "route")]
    NewRoute(RouteMessage),
    #[cfg(feature = "route")]
    DelRoute(RouteMessage),
    #[cfg(feature = "route")]
    GetRoute(RouteMessage),
    #[cfg(feature = "prefix")]
    NewPrefix(PrefixMessage),
    #[cfg(feature = "tc")]
    NewQueueDiscipline(TcMessage),
    #[cfg(feature = "tc")]
    DelQueueDiscipline(TcMessage),
    #[cfg(feature = "tc")]
    GetQueueDiscipline(TcMessage),
    #[cfg(feature = "tc")]
    NewTrafficClass(TcMessage),
    #[cfg(feature = "tc")]
    DelTrafficClass(TcMessage),
    #[cfg(feature = "tc")]
    GetTrafficClass(TcMessage),
    #[cfg(feature = "tc")]
    NewTrafficFilter(TcMessage),
    #[cfg(feature = "tc")]
    DelTrafficFilter(TcMessage),
    #[cfg(feature = "tc")]
    GetTrafficFilter(TcMessage),
    #[cfg(feature = "tc")]
    NewTrafficAction(TcActionMessage),
    #[cfg(feature = "tc")]
    DelTrafficAction(TcActionMessage),
    #[cfg(feature = "tc")]
    GetTrafficAction(TcActionMessage),
    #[cfg(feature = "tc")]
    NewTrafficChain(TcMessage),
    #[cfg(feature = "tc")]
    DelTrafficChain(TcMessage),
    #[cfg(feature = "tc")]
    GetTrafficChain(TcMessage),
    #[cfg(feature = "stats")]
    NewStats(StatsMessage),
    #[cfg(feature = "stats")]
    GetStats(StatsMessage),
    #[cfg(feature = "nsid")]
    NewNsId(NsidMessage),
    #[cfg(feature = "nsid")]
    DelNsId(NsidMessage),
    #[cfg(feature = "nsid")]
    GetNsId(NsidMessage),
    #[cfg(feature = "rule")]
    NewRule(RuleMessage),
    #[cfg(feature = "rule")]
    DelRule(RuleMessage),
    #[cfg(feature = "rule")]
    GetRule(RuleMessage),
}

impl RouteNetlinkMessage {
    #[cfg(feature = "link")]
    pub fn is_new_link(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewLink(_))
    }

    #[cfg(feature = "link")]
    pub fn is_del_link(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelLink(_))
    }

    #[cfg(feature = "link")]
    pub fn is_get_link(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetLink(_))
    }

    #[cfg(feature = "link")]
    pub fn is_set_link(&self) -> bool {
        matches!(self, RouteNetlinkMessage::SetLink(_))
    }

    #[cfg(feature = "address")]
    pub fn is_new_address(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewAddress(_))
    }

    #[cfg(feature = "address")]
    pub fn is_del_address(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelAddress(_))
    }

    #[cfg(feature = "address")]
    pub fn is_get_address(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetAddress(_))
    }

    #[cfg(feature = "addrlabel")]
    pub fn is_new_addr_label(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewAddrLabel(_))
    }

    #[cfg(feature = "addrlabel")]
    pub fn is_del_addr_label(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelAddrLabel(_))
    }

    #[cfg(feature = "addrlabel")]
    pub fn is_get_addr_label(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetAddrLabel(_))
    }

    #[cfg(feature = "neighbour")]
    pub fn is_get_neighbour(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetNeighbour(_))
    }

    #[cfg(feature = "route")]
    pub fn is_new_route(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewRoute(_))
    }

    #[cfg(feature = "neighbour")]
    pub fn is_new_neighbour(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewNeighbour(_))
    }

    #[cfg(feature = "route")]
    pub fn is_get_route(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetRoute(_))
    }

    #[cfg(feature = "neighbour")]
    pub fn is_del_neighbour(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelNeighbour(_))
    }

    #[cfg(feature = "neighbour-table")]
    pub fn is_new_neighbour_table(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewNeighbourTable(_))
    }

    #[cfg(feature = "neighbour-table")]
    pub fn is_get_neighbour_table(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetNeighbourTable(_))
    }

    #[cfg(feature = "neighbour-table")]
    pub fn is_set_neighbour_table(&self) -> bool {
        matches!(self, RouteNetlinkMessage::SetNeighbourTable(_))
    }

    #[cfg(feature = "route")]
    pub fn is_del_route(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelRoute(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_new_qdisc(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewQueueDiscipline(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_del_qdisc(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelQueueDiscipline(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_get_qdisc(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetQueueDiscipline(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_new_class(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewTrafficClass(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_del_class(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelTrafficClass(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_get_class(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetTrafficClass(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_new_filter(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewTrafficFilter(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_del_filter(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelTrafficFilter(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_get_filter(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetTrafficFilter(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_new_action(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewTrafficAction(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_del_action(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelTrafficAction(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_get_action(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetTrafficAction(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_new_chain(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewTrafficChain(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_del_chain(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelTrafficChain(_))
    }

    #[cfg(feature = "tc")]
    pub fn is_get_chain(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetTrafficChain(_))
    }

    #[cfg(feature = "nsid")]
    pub fn is_new_nsid(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewNsId(_))
    }

    #[cfg(feature = "nsid")]
    pub fn is_get_nsid(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetNsId(_))
    }

    #[cfg(feature = "nsid")]
    pub fn is_del_nsid(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelNsId(_))
    }

    #[cfg(feature = "rule")]
    pub fn is_get_rule(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetRule(_))
    }

    #[cfg(feature = "rule")]
    pub fn is_new_rule(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewRule(_))
    }

    #[cfg(feature = "rule")]
    pub fn is_del_rule(&self) -> bool {
        matches!(self, RouteNetlinkMessage::DelRule(_))
    }

    #[cfg(feature = "stats")]
    pub fn is_new_stats(&self) -> bool {
        matches!(self, RouteNetlinkMessage::NewStats(_))
    }

    #[cfg(feature = "stats")]
    pub fn is_get_stats(&self) -> bool {
        matches!(self, RouteNetlinkMessage::GetStats(_))
    }

    pub fn message_type(&self) -> u16 {
        match *self {
            #[cfg(feature = "link")]
            Self::NewLink(_) => RTM_NEWLINK,
            #[cfg(feature = "link")]
            Self::DelLink(_) => RTM_DELLINK,
            #[cfg(feature = "link")]
            Self::GetLink(_) => RTM_GETLINK,
            #[cfg(feature = "link")]
            Self::SetLink(_) => RTM_SETLINK,
            #[cfg(feature = "link")]
            Self::NewLinkProp(_) => RTM_NEWLINKPROP,
            #[cfg(feature = "link")]
            Self::DelLinkProp(_) => RTM_DELLINKPROP,
            #[cfg(feature = "address")]
            Self::NewAddress(_) => RTM_NEWADDR,
            #[cfg(feature = "address")]
            Self::DelAddress(_) => RTM_DELADDR,
            #[cfg(feature = "address")]
            Self::GetAddress(_) => RTM_GETADDR,
            #[cfg(feature = "addrlabel")]
            Self::NewAddrLabel(_) => RTM_NEWADDRLABEL,
            #[cfg(feature = "addrlabel")]
            Self::DelAddrLabel(_) => RTM_DELADDRLABEL,
            #[cfg(feature = "addrlabel")]
            Self::GetAddrLabel(_) => RTM_GETADDRLABEL,
            #[cfg(feature = "neighbour")]
            Self::GetNeighbour(_) => RTM_GETNEIGH,
            #[cfg(feature = "neighbour")]
            Self::NewNeighbour(_) => RTM_NEWNEIGH,
            #[cfg(feature = "neighbour")]
            Self::DelNeighbour(_) => RTM_DELNEIGH,
            #[cfg(feature = "neighbour-table")]
            Self::GetNeighbourTable(_) => RTM_GETNEIGHTBL,
            #[cfg(feature = "neighbour-table")]
            Self::NewNeighbourTable(_) => RTM_NEWNEIGHTBL,
            #[cfg(feature = "neighbour-table")]
            Self::SetNeighbourTable(_) => RTM_SETNEIGHTBL,
            #[cfg(feature = "route")]
            Self::NewRoute(_) => RTM_NEWROUTE,
            #[cfg(feature = "route")]
            Self::DelRoute(_) => RTM_DELROUTE,
            #[cfg(feature = "route")]
            Self::GetRoute(_) => RTM_GETROUTE,
            #[cfg(feature = "prefix")]
            Self::NewPrefix(_) => RTM_NEWPREFIX,
            #[cfg(feature = "tc")]
            Self::NewQueueDiscipline(_) => RTM_NEWQDISC,
            #[cfg(feature = "tc")]
            Self::DelQueueDiscipline(_) => RTM_DELQDISC,
            #[cfg(feature = "tc")]
            Self::GetQueueDiscipline(_) => RTM_GETQDISC,
            #[cfg(feature = "tc")]
            Self::NewTrafficClass(_) => RTM_NEWTCLASS,
            #[cfg(feature = "tc")]
            Self::DelTrafficClass(_) => RTM_DELTCLASS,
            #[cfg(feature = "tc")]
            Self::GetTrafficClass(_) => RTM_GETTCLASS,
            #[cfg(feature = "tc")]
            Self::NewTrafficFilter(_) => RTM_NEWTFILTER,
            #[cfg(feature = "tc")]
            Self::DelTrafficFilter(_) => RTM_DELTFILTER,
            #[cfg(feature = "tc")]
            Self::GetTrafficFilter(_) => RTM_GETTFILTER,
            #[cfg(feature = "tc")]
            Self::NewTrafficAction(_) => RTM_NEWACTION,
            #[cfg(feature = "tc")]
            Self::DelTrafficAction(_) => RTM_DELACTION,
            #[cfg(feature = "tc")]
            Self::GetTrafficAction(_) => RTM_GETACTION,
            #[cfg(feature = "tc")]
            Self::NewTrafficChain(_) => RTM_NEWCHAIN,
            #[cfg(feature = "tc")]
            Self::DelTrafficChain(_) => RTM_DELCHAIN,
            #[cfg(feature = "tc")]
            Self::GetTrafficChain(_) => RTM_GETCHAIN,
            #[cfg(feature = "nsid")]
            Self::GetNsId(_) => RTM_GETNSID,
            #[cfg(feature = "nsid")]
            Self::NewNsId(_) => RTM_NEWNSID,
            #[cfg(feature = "nsid")]
            Self::DelNsId(_) => RTM_DELNSID,
            #[cfg(feature = "stats")]
            Self::NewStats(_) => RTM_NEWSTATS,
            #[cfg(feature = "stats")]
            Self::GetStats(_) => RTM_GETSTATS,
            #[cfg(feature = "rule")]
            Self::GetRule(_) => RTM_GETRULE,
            #[cfg(feature = "rule")]
            Self::NewRule(_) => RTM_NEWRULE,
            #[cfg(feature = "rule")]
            Self::DelRule(_) => RTM_DELRULE,
        }
    }
}

impl Emitable for RouteNetlinkMessage {
    fn buffer_len(&self) -> usize {
        match *self {
            #[cfg(feature = "link")]
            Self::NewLink(ref msg)
            | Self::DelLink(ref msg)
            | Self::GetLink(ref msg)
            | Self::SetLink(ref msg)
            | Self::NewLinkProp(ref msg)
            | Self::DelLinkProp(ref msg) => msg.buffer_len(),

            #[cfg(feature = "address")]
            Self::NewAddress(ref msg)
            | Self::DelAddress(ref msg)
            | Self::GetAddress(ref msg) => msg.buffer_len(),

            #[cfg(feature = "addrlabel")]
            Self::NewAddrLabel(ref msg)
            | Self::DelAddrLabel(ref msg)
            | Self::GetAddrLabel(ref msg) => msg.buffer_len(),

            #[cfg(feature = "neighbour")]
            Self::NewNeighbour(ref msg)
            | Self::GetNeighbour(ref msg)
            | Self::DelNeighbour(ref msg) => msg.buffer_len(),

            #[cfg(feature = "neighbour-table")]
            Self::NewNeighbourTable(ref msg)
            | Self::GetNeighbourTable(ref msg)
            | Self::SetNeighbourTable(ref msg) => msg.buffer_len(),

            #[cfg(feature = "route")]
            Self::NewRoute(ref msg)
            | Self::DelRoute(ref msg)
            | Self::GetRoute(ref msg) => msg.buffer_len(),

            #[cfg(feature = "prefix")]
            Self::NewPrefix(ref msg) => msg.buffer_len(),

            #[cfg(feature = "tc")]
            Self::NewQueueDiscipline(ref msg)
            | Self::DelQueueDiscipline(ref msg)
            | Self::GetQueueDiscipline(ref msg)
            | Self::NewTrafficClass(ref msg)
            | Self::DelTrafficClass(ref msg)
            | Self::GetTrafficClass(ref msg)
            | Self::NewTrafficFilter(ref msg)
            | Self::DelTrafficFilter(ref msg)
            | Self::GetTrafficFilter(ref msg)
            | Self::NewTrafficChain(ref msg)
            | Self::DelTrafficChain(ref msg)
            | Self::GetTrafficChain(ref msg) => msg.buffer_len(),

            #[cfg(feature = "nsid")]
            Self::NewNsId(ref msg)
            | Self::DelNsId(ref msg)
            | Self::GetNsId(ref msg) => msg.buffer_len(),

            #[cfg(feature = "stats")]
            Self::NewStats(ref msg) | Self::GetStats(ref msg) => {
                msg.buffer_len()
            }

            #[cfg(feature = "rule")]
            Self::NewRule(ref msg)
            | Self::DelRule(ref msg)
            | Self::GetRule(ref msg) => msg.buffer_len(),

            #[cfg(feature = "tc")]
            Self::NewTrafficAction(ref msg)
            | Self::DelTrafficAction(ref msg)
            | Self::GetTrafficAction(ref msg) => msg.buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        let _ = &buffer; // The empty feature set has no variants to emit.
        match *self {
            #[cfg(feature = "link")]
            Self::NewLink(ref msg)
            | Self::DelLink(ref msg)
            | Self::GetLink(ref msg)
            | Self::SetLink(ref msg)
            | Self::NewLinkProp(ref msg)
            | Self::DelLinkProp(ref msg) => msg.emit(buffer),

            #[cfg(feature = "address")]
            Self::NewAddress(ref msg)
            | Self::DelAddress(ref msg)
            | Self::GetAddress(ref msg) => msg.emit(buffer),

            #[cfg(feature = "addrlabel")]
            Self::NewAddrLabel(ref msg)
            | Self::DelAddrLabel(ref msg)
            | Self::GetAddrLabel(ref msg) => msg.emit(buffer),

            #[cfg(feature = "neighbour")]
            Self::GetNeighbour(ref msg)
            | Self::NewNeighbour(ref msg)
            | Self::DelNeighbour(ref msg) => msg.emit(buffer),

            #[cfg(feature = "neighbour-table")]
            Self::GetNeighbourTable(ref msg)
            | Self::NewNeighbourTable(ref msg)
            | Self::SetNeighbourTable(ref msg) => msg.emit(buffer),

            #[cfg(feature = "route")]
            Self::NewRoute(ref msg)
            | Self::DelRoute(ref msg)
            | Self::GetRoute(ref msg) => msg.emit(buffer),

            #[cfg(feature = "prefix")]
            Self::NewPrefix(ref msg) => msg.emit(buffer),

            #[cfg(feature = "tc")]
            Self::NewQueueDiscipline(ref msg)
            | Self::DelQueueDiscipline(ref msg)
            | Self::GetQueueDiscipline(ref msg)
            | Self::NewTrafficClass(ref msg)
            | Self::DelTrafficClass(ref msg)
            | Self::GetTrafficClass(ref msg)
            | Self::NewTrafficFilter(ref msg)
            | Self::DelTrafficFilter(ref msg)
            | Self::GetTrafficFilter(ref msg)
            | Self::NewTrafficChain(ref msg)
            | Self::DelTrafficChain(ref msg)
            | Self::GetTrafficChain(ref msg) => msg.emit(buffer),

            #[cfg(feature = "nsid")]
            Self::NewNsId(ref msg)
            | Self::DelNsId(ref msg)
            | Self::GetNsId(ref msg) => msg.emit(buffer),

            #[cfg(feature = "stats")]
            Self::NewStats(ref msg) | Self::GetStats(ref msg) => {
                msg.emit(buffer)
            }

            #[cfg(feature = "rule")]
            Self::NewRule(ref msg)
            | Self::DelRule(ref msg)
            | Self::GetRule(ref msg) => msg.emit(buffer),

            #[cfg(feature = "tc")]
            Self::NewTrafficAction(ref msg)
            | Self::DelTrafficAction(ref msg)
            | Self::GetTrafficAction(ref msg) => msg.emit(buffer),
        }
    }
}

impl NetlinkSerializable for RouteNetlinkMessage {
    fn message_type(&self) -> u16 {
        self.message_type()
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable for RouteNetlinkMessage {
    type Error = DecodeError;
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error> {
        RouteNetlinkMessage::parse_with_param(payload, header.message_type)
    }
}

impl From<RouteNetlinkMessage> for NetlinkPayload<RouteNetlinkMessage> {
    fn from(message: RouteNetlinkMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
