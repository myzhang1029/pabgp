//! BGP open message optional parameters and the capability parameter
//!
//! RFC 4271 Section 4.2 specifies the optional parameters that can be included in the BGP open message.
//! However, the only optional parameter defined is the capability parameter (RFC 3392/5492), so both are
//! implemented in this module.

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    check_remaining_len,
    endec::{self, Component},
};
use bytes::{Buf, BufMut, Bytes};
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use std::ops::Deref;

/// A list of BGP optional parameters
#[derive(Clone, Debug, PartialEq)]
pub struct OptionalParameters(Vec<OptionalParameterValue>);

impl Component for OptionalParameters {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        // RFC 4271 4.2 Optional Parameters Length
        let len = src.get_u8() as usize;
        check_remaining_len!(src, len, "optional parameter length");
        let mut opt_params = Vec::new();
        // RFC 4271 4.2 Optional Parameters
        while src.has_remaining() {
            let param = OptionalParameterValue::from_bytes(src)?;
            opt_params.push(param);
        }
        Ok(Self(opt_params))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        let length_pos = dst.len();
        dst.put_u8(0); // Placeholder for length
        for param in self.0 {
            len += param.to_bytes(dst);
        }
        dst[length_pos] = u8::try_from(len).expect("Optional parameters length overflow");
        len + 1 // Length
    }
}

impl Deref for OptionalParameters {
    type Target = Vec<OptionalParameterValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BGP optional parameter (RFC 4271 4.2)
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum OptionalParameterValue {
    Capabilities(Capabilities),
}

/// BGP optional parameter types
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[non_exhaustive]
#[repr(u8)]
pub enum OptionalParameterType {
    Capabilities = 2,
}

impl Component for OptionalParameterValue {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        // RFC 5492 4. Optional Parameters -> Parameter Type
        let param_type = src.get_u8();
        // RFC 5492 4. Optional Parameters -> Parameter Length
        let param_len = src.get_u8() as usize;
        check_remaining_len!(src, param_len, "optional parameter");
        match OptionalParameterType::from_u8(param_type) {
            Some(OptionalParameterType::Capabilities) => {
                let cap = Capabilities::from_bytes(src)?;
                Ok(Self::Capabilities(cap))
            }
            _ => Err(endec::Error::InternalType(
                "optional parameter",
                u16::from(param_type),
            )),
        }
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let type_pos = dst.len();
        dst.put_u8(0); // Placeholder for type
        let len_pos = dst.len();
        dst.put_u8(0); // Placeholder for length
        match self {
            OptionalParameterValue::Capabilities(cap) => {
                let len = cap.to_bytes(dst);
                dst[type_pos] = OptionalParameterType::Capabilities as u8;
                dst[len_pos] = u8::try_from(len).expect("Capabilities length overflow");
                len + 2 // Type and length
            }
        }
    }
}

/// BGP capability
// "a BGP speaker MUST be prepared to accept such multiple instances," so a Vec must be used
#[derive(Clone, Debug, PartialEq)]
pub struct Capabilities(Vec<Value>);

impl Component for Capabilities {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let mut cap = Vec::new();
        while src.has_remaining() {
            // RFC 5492 4. Optional Parameters -> Capability Code
            let code = src.get_u8();
            // RFC 5492 4. Optional Parameters -> Capability Length
            let len = src.get_u8() as usize;
            // Avoid processing trailing bytes
            let mut src = src.split_to(len);
            check_remaining_len!(src, len, "capability");
            log::trace!("Capability code: {code}, length: {len}, data: {src:?}");
            let value = match Type::from_u8(code) {
                Some(Type::MultiProtocol) => {
                    Value::MultiProtocol(MultiProtocol::from_bytes(&mut src)?)
                }
                Some(Type::RouteRefresh) => Value::RouteRefresh,
                Some(Type::ExtendedNextHop) => {
                    Value::ExtendedNextHop(ExtendedNextHop::from_bytes(&mut src)?)
                }
                Some(Type::ExtendedMessage) => Value::ExtendedMessage,
                Some(Type::FourOctetAsNumber) => {
                    Value::FourOctetAsNumber(FourOctetAsNumber { asn: src.get_u32() })
                }
                _ => Value::Unsupported(code, src.copy_to_bytes(src.len())),
            };
            cap.push(value);
        }
        Ok(Self(cap))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        for value in self.0 {
            dst.put_u8((&value).into());
            let len_pos = dst.len();
            dst.put_u8(0); // Placeholder for length
            let value_len = match value {
                Value::MultiProtocol(mp) => mp.to_bytes(dst),
                Value::RouteRefresh | Value::ExtendedMessage => 0,
                Value::ExtendedNextHop(enh) => enh.to_bytes(dst),
                Value::FourOctetAsNumber(four) => four.asn.to_bytes(dst),
                Value::Unsupported(_, data) => {
                    dst.put_slice(&data);
                    data.len()
                }
            };
            dst[len_pos] = u8::try_from(value_len).expect("Capability length overflow");
            len += value_len + 2; // Code and length
        }
        len
    }
}

impl Deref for Capabilities {
    type Target = Vec<Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BGP capability (RFC 3392/5492)
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// BGP multi-protocol capability (RFC 2858)
    MultiProtocol(MultiProtocol),
    /// BGP route refresh capability (RFC 2918)
    RouteRefresh,
    /// BGP extended next hop capability (RFC 8950)
    ExtendedNextHop(ExtendedNextHop),
    /// BGP extended message capability (RFC 8654)
    ExtendedMessage,
    /// BGP four-octet AS number capability (RFC 6793)
    FourOctetAsNumber(FourOctetAsNumber),
    /// Other unsupported capability
    Unsupported(u8, Bytes),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[non_exhaustive]
#[repr(u8)]
pub enum Type {
    MultiProtocol = 1,
    RouteRefresh = 2,
    ExtendedNextHop = 5,
    ExtendedMessage = 6,
    FourOctetAsNumber = 65,
}

impl From<&Value> for u8 {
    fn from(cap: &Value) -> Self {
        match cap {
            Value::MultiProtocol(_) => Type::MultiProtocol as u8,
            Value::RouteRefresh => Type::RouteRefresh as u8,
            Value::ExtendedNextHop(_) => Type::ExtendedNextHop as u8,
            Value::ExtendedMessage => Type::ExtendedMessage as u8,
            Value::FourOctetAsNumber(_) => Type::FourOctetAsNumber as u8,
            Value::Unsupported(code, _) => *code,
        }
    }
}

/// BGP multi-protocol capability value field (RFC 2858 Section 7)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MultiProtocol {
    pub afi: Afi,
    pub safi: Safi,
}

impl Component for MultiProtocol {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let afi = src.get_u16();
        let afi =
            Afi::try_from(afi).map_err(|_| endec::Error::InternalType("MultiProtocol AFI", afi))?;
        let _ = src.get_u8(); // Reserved
        let safi = src.get_u8().into();
        let safi = Safi::try_from(safi)
            .map_err(|_| endec::Error::InternalType("MultiProtocol SAFI", safi))?;
        Ok(Self { afi, safi })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        dst.put_u16(self.afi as u16);
        dst.put_u8(0); // Reserved
        dst.put_u8(self.safi as u8);
        4
    }
}

/// BGP address family identifier
///
/// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[non_exhaustive]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

/// BGP subsequent address family identifier
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[non_exhaustive]
#[repr(u16)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    MplsLabel = 4,
    Vpn = 128,
    VpnMulticast = 129,
}

/// BGP extended next hop capability (RFC 8950)
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedNextHop(pub Vec<ExtendedNextHopValue>);

/// BGP extended next hop value field (RFC 8950)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExtendedNextHopValue {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop_afi: Afi,
}

impl Component for ExtendedNextHop {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, endec::Error> {
        let mut values = Vec::with_capacity(src.len() / 6);
        while src.has_remaining() {
            let afi = src.get_u16();
            let afi = Afi::try_from(afi)
                .map_err(|_| endec::Error::InternalType("ExtendedNextHop AFI", afi))?;
            let safi = src.get_u16();
            let safi = Safi::try_from(safi)
                .map_err(|_| endec::Error::InternalType("ExtendedNextHop SAFI", safi))?;
            let next_hop_afi = src.get_u16();
            let next_hop_afi = Afi::try_from(next_hop_afi).map_err(|_| {
                endec::Error::InternalType("ExtendedNextHop NextHop AFI", next_hop_afi)
            })?;
            values.push(ExtendedNextHopValue {
                afi,
                safi,
                next_hop_afi,
            });
        }
        Ok(Self(values))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        for value in self.0 {
            dst.put_u16(value.afi as u16);
            dst.put_u16(value.safi as u16);
            dst.put_u16(value.next_hop_afi as u16);
            len += 6;
        }
        len
    }
}

/// BGP four-octet AS number capability value field (RFC 6793)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FourOctetAsNumber {
    pub asn: u32,
}
