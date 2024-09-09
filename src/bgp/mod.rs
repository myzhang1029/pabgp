//! BGP packet structures
//!
//! Structs here intends to represent the data instead of the on-wire format.

// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod builder;
pub mod capability;
mod endec;
pub mod path;
pub mod route;
#[cfg(test)]
mod tests;

pub use endec::{BgpCodec as Codec, Error};
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;

use crate::check_remaining_len;
use bytes::{Buf, BufMut};
use capability::{Capabilities, OptionalParameters};
use endec::Component;
use path::PathAttributes;
use route::Routes;
use std::net::Ipv4Addr;

/// Supported BGP version
pub const BGP_VERSION: u8 = 4;

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
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub opt_params: OptionalParameters,
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

impl Open {
    /// Create a new BGP open message
    pub fn new_easy(
        asn: u32,
        hold_time: u16,
        bgp_id: Ipv4Addr,
        capabilities: Capabilities,
    ) -> Self {
        let oldbgp_asn = if asn > u32::from(u16::MAX) {
            AS_TRANS
        } else {
            u16::try_from(asn).expect("Impossible to overflow")
        };
        Self {
            version: BGP_VERSION,
            asn: oldbgp_asn,
            hold_time,
            bgp_id,
            opt_params: vec![capability::OptionalParameterValue::Capabilities(
                capabilities,
            )]
            .into(),
        }
    }
}

/// BGP update message
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub withdrawn_routes: Routes,
    pub path_attributes: PathAttributes,
    pub nlri: Routes,
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
    pub error_code: NotificationErrorCode,
    pub error_subcode: u8,
    pub data: bytes::Bytes,
}

impl Component for Notification {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let error_code = src.get_u8();
        let error_subcode = src.get_u8();
        let data = src.copy_to_bytes(src.remaining());
        Ok(Self {
            error_code: NotificationErrorCode::from_u8(error_code)
                .ok_or_else(|| endec::Error::InternalType("error_code", u16::from(error_code)))?,
            error_subcode,
            data,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        len += (self.error_code as u8).to_bytes(dst);
        len += self.error_subcode.to_bytes(dst);
        len += self.data.len();
        dst.put_slice(&self.data);
        len
    }
}

impl Notification {
    /// Create a new BGP notification message
    pub fn new(error_code: NotificationErrorCode, error_subcode: u8, data: bytes::Bytes) -> Self {
        Self {
            error_code,
            error_subcode,
            data,
        }
    }
}

/// Notification error codes
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum NotificationErrorCode {
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6,
}

/// Notification error subcodes for MessageHeaderError
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum MessageHeaderErrorSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

/// Notification error subcodes for OpenMessageError
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum OpenMessageErrorSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

/// Notification error subcodes for UpdateMessageError
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum UpdateMessageErrorSubcode {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    AsRoutingLoop = 7,
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

/// Notification error subcodes for Cease
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum CeaseSubcode {
    MaximumNumberOfPrefixesReached = 1,
    AdministrativeShutdown = 2,
    PeerDeconfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollisionResolution = 7,
    OutOfResources = 8,
}
