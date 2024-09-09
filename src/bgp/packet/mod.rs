//! BGP packet structures
//!
//! Structs here intends to represent the data instead of the on-wire format.

// SPDX-License-Identifier: AGPL-3.0-or-later

mod capability;
mod endec;
mod path;
mod route;
#[cfg(test)]
mod tests;

use crate::check_remaining_len;
use bytes::{Buf, BufMut};
use capability::OptionalParameters;
use endec::Component;
use path::PathAttributes;
use route::Routes;
use std::net::Ipv4Addr;

/// ASN for AS4
pub const AS_TRANS: u16 = 23456;

/// BGP message
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Open(Open),
    Update(Update),
    Notification(Notification),
    Keepalive,
}

/// BGP open message
#[derive(Clone, Debug, PartialEq)]
pub struct Open {
    version: u8,
    asn: u16,
    hold_time: u16,
    bgp_id: Ipv4Addr,
    opt_params: OptionalParameters,
}

impl Component for Open {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let version = src.get_u8();
        let asn = src.get_u16();
        let hold_time = src.get_u16();
        let bgp_id = Ipv4Addr::from(src.get_u32());
        let opt_params = OptionalParameters::from_bytes(src)?;
        Ok(Self {
            version,
            asn,
            hold_time,
            bgp_id,
            opt_params,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        len += self.version.to_bytes(dst);
        len += self.asn.to_bytes(dst);
        len += self.hold_time.to_bytes(dst);
        len += self.bgp_id.to_bytes(dst);
        len += self.opt_params.to_bytes(dst);
        len
    }
}

/// BGP update message
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    withdrawn_routes: Routes,
    path_attributes: PathAttributes,
    nlri: Routes,
}

impl Component for Update {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let withdrawn_len = src.get_u16() as usize;
        let mut wdr_buf = src.split_to(withdrawn_len);
        let withdrawn_routes = Routes::from_bytes(&mut wdr_buf)?;
        let tpa_len = src.get_u16() as usize;
        let mut tpa_buf = src.split_to(tpa_len);
        let path_attributes = PathAttributes::from_bytes(&mut tpa_buf)?;
        let nlri = Routes::from_bytes(src)?;
        Ok(Self {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        let wdr_len_pos = dst.len();
        len += 0u16.to_bytes(dst); // Placeholder for withdrawn routes length
        let wdr_len = self.withdrawn_routes.to_bytes(dst);
        len += wdr_len;
        dst[wdr_len_pos..wdr_len_pos + 2].copy_from_slice(
            &(u16::try_from(wdr_len)
                .expect("Withdrawn routes length overflow")
                .to_be_bytes()),
        );
        let tpa_len_pos = dst.len();
        len += 0u16.to_bytes(dst); // Placeholder for total path attributes length
        let tpa_len = self.path_attributes.to_bytes(dst);
        len += tpa_len;
        dst[tpa_len_pos..tpa_len_pos + 2].copy_from_slice(
            &(u16::try_from(tpa_len)
                .expect("Total path attributes length overflow")
                .to_be_bytes()),
        );
        len += self.nlri.to_bytes(dst);
        len
    }
}

/// BGP notification message
#[derive(Clone, Debug, PartialEq)]
pub struct Notification {
    error_code: u8,
    error_subcode: u8,
    data: bytes::Bytes,
}

impl Component for Notification {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let error_code = src.get_u8();
        let error_subcode = src.get_u8();
        let data = src.clone();
        Ok(Self {
            error_code,
            error_subcode,
            data,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        len += self.error_code.to_bytes(dst);
        len += self.error_subcode.to_bytes(dst);
        len += self.data.len();
        dst.put_slice(&self.data);
        len
    }
}
