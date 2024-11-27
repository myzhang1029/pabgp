//! PABGP -- The pretty average BGP implementation
//!
//! Structs here intends to represent the data instead of the on-wire format.

// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod capability;
pub mod cidr;
mod endec;
#[cfg(test)]
#[cfg(feature = "tokio-endec")]
mod endec_tests;
pub mod path;
pub mod route;
mod update_builder;

#[cfg(feature = "tokio-endec")]
pub use endec::BgpCodec as Codec;
pub use update_builder::UpdateBuilder;

use bytes::{Buf, BufMut};
use capability::{Capabilities, OptionalParameters};
use endec::Component;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use path::PathAttributes;
use route::Routes;
use std::net::Ipv4Addr;

/// Supported BGP version
pub const BGP_VERSION: u8 = 4;

/// ASN for AS4
pub const AS_TRANS: u16 = 23456;

/// BGP marker
pub const MARKER: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// BGP packet errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid or missing marker")]
    Marker,
    #[error("invalid message type")]
    MessageType(u8),
    #[error("invalid internal length at {0} ({1:?})")]
    InternalLength(&'static str, std::cmp::Ordering),
    #[error("invalid {0} type of {1}")]
    InternalType(&'static str, u16),
    #[error("requires MP-BGP capability")]
    NoMpBgp,
    #[error("attempting to update NLRI without next hop")]
    NoNextHop,
}

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
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, crate::Error> {
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

    fn encoded_len(&self) -> usize {
        1 + 2 + 2 + 4 + self.opt_params.encoded_len()
    }
}

impl Open {
    /// Create a new BGP open message
    #[must_use]
    pub fn new_easy(
        asn: u32,
        hold_time: u16,
        bgp_id: Ipv4Addr,
        capabilities: Capabilities,
    ) -> Self {
        let oldbgp_asn = u16::try_from(asn).unwrap_or(AS_TRANS);
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
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, crate::Error> {
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

    fn encoded_len(&self) -> usize {
        2 + self.withdrawn_routes.encoded_len()
            + 2
            + self.path_attributes.encoded_len()
            + self.nlri.encoded_len()
    }
}

/// BGP notification message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub error_code: NotificationErrorCode,
    pub error_subcode: u8,
    pub data: bytes::Bytes,
}

impl Component for Notification {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, crate::Error> {
        let error_code = src.get_u8();
        let error_subcode = src.get_u8();
        let data = src.copy_to_bytes(src.remaining());
        Ok(Self {
            error_code: NotificationErrorCode::from_u8(error_code)
                .ok_or_else(|| crate::Error::InternalType("error_code", u16::from(error_code)))?,
            error_subcode,
            data,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        (self.error_code as u8).to_bytes(dst);
        self.error_subcode.to_bytes(dst);
        dst.put_slice(&self.data);
        self.encoded_len()
    }

    fn encoded_len(&self) -> usize {
        2 + self.data.len()
    }
}

impl Notification {
    /// Create a new BGP notification message
    pub const fn new(error_code: NotificationErrorCode, error_subcode: u8, data: bytes::Bytes) -> Self {
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

/// Notification error subcodes for `MessageHeaderError`
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum MessageHeaderErrorSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

/// Notification error subcodes for `OpenMessageError`
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum OpenMessageErrorSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

/// Notification error subcodes for `UpdateMessageError`
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

#[cfg(test)]
const fn convert_one_hex_digit(c: u8) -> u8 {
    if c.is_ascii_digit() {
        c - b'0'
    } else if c.is_ascii_lowercase() {
        c - b'a' + 10
    } else if c.is_ascii_uppercase() {
        c - b'A' + 10
    } else {
        panic!("invalid hex character");
    }
}

#[cfg(test)]
#[must_use]
pub fn hex_to_bytes(hex: &str) -> bytes::Bytes {
    // Skip these characters on octet boundary
    const SKIP: &[u8] = b" \t\n\r:.";
    let hex = hex.as_bytes();
    let mut octets = bytes::BytesMut::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        let c = hex[i];
        if SKIP.contains(&c) {
            i += 1;
            continue;
        }
        let hi = convert_one_hex_digit(c) << 4;
        assert!(i + 1 < hex.len(), "odd number of hex digits");
        let lo = convert_one_hex_digit(hex[i + 1]);
        octets.put_u8(hi | lo);
        i += 2;
    }
    octets.freeze()
}
