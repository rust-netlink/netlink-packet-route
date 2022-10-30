// SPDX-License-Identifier: MIT

use super::link_attrs::LinkAttrs;

pub trait Link: Send + Sync {
    fn attrs(&self) -> &LinkAttrs;
    fn set_attrs(&mut self, attr: LinkAttrs);
    fn r#type(&self) -> &str;
}

macro_rules! impl_network_dev {
    ($r_type: literal , $r_struct: ty) => {
        impl Link for $r_struct {
            fn attrs(&self) -> &LinkAttrs {
                self.attrs.as_ref().unwrap()
            }
            fn set_attrs(&mut self, attr: LinkAttrs) {
                self.attrs = Some(attr);
            }
            fn r#type(&self) -> &'static str {
                $r_type
            }
        }
    };
}

macro_rules! define_and_impl_network_dev {
    ($r_type: literal , $r_struct: tt) => {
        #[derive(Debug, PartialEq, Eq, Clone, Default)]
        pub struct $r_struct {
            attrs: Option<LinkAttrs>,
        }

        impl_network_dev!($r_type, $r_struct);
    };
}

define_and_impl_network_dev!("device", Device);
define_and_impl_network_dev!("tuntap", Tuntap);
define_and_impl_network_dev!("veth", Veth);
define_and_impl_network_dev!("ipvlan", IpVlan);
define_and_impl_network_dev!("macvlan", MacVlan);
define_and_impl_network_dev!("vlan", Vlan);

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Bridge {
    attrs: Option<LinkAttrs>,
    pub multicast_snooping: bool,
    pub hello_time: u32,
    pub vlan_filtering: bool,
}

impl_network_dev!("bridge", Bridge);
