//! BGP path attributes (RFC 4271 Section 4.3)

// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    capability::{Afi, Safi},
    endec::Component,
    route::Routes,
};
use bytes::{Buf, BufMut, Bytes};
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

/// BGP path attributes
#[derive(Clone, Debug, Default, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub struct PathAttributes(pub Vec<Value>);

impl Component for PathAttributes {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let mut attributes = Vec::new();
        while src.has_remaining() {
            attributes.push(Value::from_bytes(src)?);
        }
        Ok(Self(attributes))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        for attribute in self.0 {
            len += attribute.to_bytes(dst);
        }
        len
    }

    fn encoded_len(&self) -> usize {
        self.0.iter().map(Value::encoded_len).sum()
    }
}

impl Deref for PathAttributes {
    type Target = Vec<Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BGP path attribute
#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    pub flags: Flags,
    pub data: Data,
}

impl Component for Value {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let flags = Flags(src.get_u8());
        let type_ = src.get_u8();
        let len = if flags.is_extended_length() {
            src.get_u16() as usize
        } else {
            src.get_u8() as usize
        };
        let mut src = src.split_to(len);
        let data = match Type::from_u8(type_) {
            Some(Type::Origin) => Data::Origin(Origin::from_bytes(&mut src)?),
            Some(Type::AsPath) => Data::AsPath(AsPath::from_bytes(&mut src)?),
            Some(Type::NextHop) => Data::NextHop(Ipv4Addr::from_bytes(&mut src)?),
            Some(Type::MultiExitDisc) => Data::MultiExitDisc(src.get_u32()),
            Some(Type::LocalPref) => Data::LocalPref(src.get_u32()),
            Some(Type::AtomicAggregate) => Data::AtomicAggregate,
            Some(Type::Aggregator) => Data::Aggregator(Aggregator::from_bytes(&mut src)?),
            Some(Type::MpReachNlri) => Data::MpReachNlri(MpReachNlri::from_bytes(&mut src)?),
            Some(Type::MpUnreachNlri) => Data::MpUnreachNlri(MpUnreachNlri::from_bytes(&mut src)?),
            Some(Type::As4Path) => Data::As4Path(AsPath::from_bytes(&mut src)?),
            // Some(Type::As4Aggregator) => Data::As4Aggregator(Aggregator::from_bytes(&mut src)?),
            _ => Data::Unsupported(type_, src),
        };
        Ok(Self { flags, data })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        dst.put_u8(self.flags.0); // Flags
        len += 1;
        dst.put_u8(u8::from(&self.data)); // Type
        len += 1;
        let len_pos = dst.len();
        let two_byte_len = if self.flags.is_extended_length() {
            dst.put_u16(0); // Placeholder for the length
            len += 2;
            true
        } else {
            dst.put_u8(0); // Placeholder for the length
            len += 1;
            false
        };
        let data_len = match self.data {
            Data::Origin(origin) => origin.to_bytes(dst),
            Data::AsPath(as_path) | Data::As4Path(as_path) => as_path.to_bytes(dst),
            Data::NextHop(next_hop) => next_hop.to_bytes(dst),
            Data::MultiExitDisc(med) => med.to_bytes(dst),
            Data::LocalPref(local_pref) => local_pref.to_bytes(dst),
            Data::AtomicAggregate => 0,
            Data::Aggregator(agg) => agg.to_bytes(dst),
            Data::MpReachNlri(mp_reach_nlri) => mp_reach_nlri.to_bytes(dst),
            Data::MpUnreachNlri(mp_unreach_nlri) => mp_unreach_nlri.to_bytes(dst),
            Data::Unsupported(_, data) => {
                let len = data.len();
                dst.unsplit(data.into());
                len
            }
        };
        if two_byte_len {
            dst[len_pos..len_pos + 2].copy_from_slice(
                &(u16::try_from(data_len)
                    .expect("Path attribute length overflow")
                    .to_be_bytes()),
            );
        } else {
            dst[len_pos] = u8::try_from(data_len).expect("Path attribute length overflow");
        }
        len + data_len
    }

    fn encoded_len(&self) -> usize {
        1 + 1
            + if self.flags.is_extended_length() {
                2
            } else {
                1
            }
            + match &self.data {
                Data::Origin(origin) => origin.encoded_len(),
                Data::AsPath(as_path) | Data::As4Path(as_path) => as_path.encoded_len(),
                Data::NextHop(next_hop) => next_hop.encoded_len(),
                Data::MultiExitDisc(_) | Data::LocalPref(_) => 4,
                Data::AtomicAggregate => 0,
                Data::Aggregator(agg) => agg.encoded_len(),
                Data::MpReachNlri(mp_reach_nlri) => mp_reach_nlri.encoded_len(),
                Data::MpUnreachNlri(mp_unreach_nlri) => mp_unreach_nlri.encoded_len(),
                Data::Unsupported(_, data) => data.len(),
            }
    }
}

/// BGP path attribute flags
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    /// Transitive, well-known, complete
    pub const WELL_KNOWN_COMPLETE: Self = Self(0b0100_0000);
    /// Optional, Extended Length, Non-transitive, Complete
    pub const OPTIONAL_TRANSITIVE_EXTENDED: Self = Self(0b1001_0000);

    /// Check if the attribute is optional
    #[must_use]
    pub const fn is_optional(self) -> bool {
        self.0 & 0x80 == 0
    }

    /// Check if the attribute is transitive
    #[must_use]
    pub const fn is_transitive(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// Check if the attribute is partial
    #[must_use]
    pub const fn is_partial(self) -> bool {
        self.0 & 0x20 != 0
    }

    /// Check if the attribute is extended length
    #[must_use]
    pub const fn is_extended_length(self) -> bool {
        self.0 & 0x10 != 0
    }
}

/// BGP path attribute data
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Data {
    Origin(Origin),
    AsPath(AsPath),
    /// BGP next hop (RFC 4271 Section 5.1.3)
    NextHop(Ipv4Addr),
    MultiExitDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator(Aggregator),
    MpReachNlri(MpReachNlri),     // RFC 4760
    MpUnreachNlri(MpUnreachNlri), // RFC 4760
    As4Path(AsPath),              // RFC 4893/6793
    // As4Aggregator(Aggregator),    // RFC 4893/6793
    Unsupported(u8, Bytes),
}

// It does not make sense to implement Component for Data because its length is given by the Flags

#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[non_exhaustive]
#[repr(u8)]
pub enum Type {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    As4Path = 17,
    // As4Aggregator = 18,
}

impl From<&Data> for u8 {
    fn from(data: &Data) -> Self {
        match data {
            Data::Origin(_) => Type::Origin as Self,
            Data::AsPath(_) => Type::AsPath as Self,
            Data::NextHop(_) => Type::NextHop as Self,
            Data::MultiExitDisc(_) => Type::MultiExitDisc as Self,
            Data::LocalPref(_) => Type::LocalPref as Self,
            Data::AtomicAggregate => Type::AtomicAggregate as Self,
            Data::Aggregator(_) => Type::Aggregator as Self,
            Data::MpReachNlri(_) => Type::MpReachNlri as Self,
            Data::MpUnreachNlri(_) => Type::MpUnreachNlri as Self,
            Data::As4Path(_) => Type::As4Path as Self,
            Data::Unsupported(type_, _) => *type_,
        }
    }
}

/// BGP origin
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl Component for Origin {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let value = src.get_u8();
        Self::from_u8(value).map_or_else(
            || Err(crate::Error::InternalType("origin", u16::from(value))),
            Ok,
        )
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        dst.put_u8(self as u8);
        self.encoded_len()
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

/// BGP AS path
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AsPath(pub Vec<AsSegment>);

impl Component for AsPath {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let mut segments = Vec::new();
        while src.has_remaining() {
            segments.push(AsSegment::from_bytes(src)?);
        }
        Ok(Self(segments))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        for segment in self.0 {
            len += segment.to_bytes(dst);
        }
        len
    }

    fn encoded_len(&self) -> usize {
        self.0.iter().map(AsSegment::encoded_len).sum()
    }
}

impl Deref for AsPath {
    type Target = Vec<AsSegment>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BGP AS path segment (RFC 4271 Section 5.1.2, RFC 6793 Section 4)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsSegment {
    pub type_: AsSegmentType,
    pub asns: Vec<u32>,
    /// Extra member to indicate that this structure was created from a 4-byte AS path
    /// or that it should be encoded as a 4-byte AS path
    pub as4: bool,
}

/// BGP AS path segment type
#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum AsSegmentType {
    AsSet = 1,
    AsSequence = 2,
    ConfedSequence = 3,
    ConfedSet = 4,
}

impl Component for AsSegment {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let type_ = src.get_u8();
        let len = src.get_u8() as usize;
        let remaining_len = src.remaining();
        // RFC 6793 Section 4 updates the AS path segment length to 2 or 4 bytes (when both peers support 4-byte ASNs)
        let per_asn_len = remaining_len / len;
        let mut asns = Vec::with_capacity(len);
        let as4 = if per_asn_len == 2 {
            for _ in 0..len {
                asns.push(u32::from(src.get_u16()));
            }
            false
        } else if per_asn_len == 4 {
            for _ in 0..len {
                asns.push(src.get_u32());
            }
            true
        } else {
            return Err(crate::Error::InternalLength(
                "AS segment",
                std::cmp::Ordering::Equal,
            ));
        };
        Ok(Self {
            type_: AsSegmentType::from_u8(type_)
                .ok_or_else(|| crate::Error::InternalType("AS segment type", u16::from(type_)))?,
            asns,
            as4,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let encoded_len = self.encoded_len();
        dst.put_u8(self.type_ as u8);
        let asns_len = self.asns.len();
        dst.put_u8(u8::try_from(asns_len).expect("AS segment length overflow"));
        for asn in self.asns {
            if self.as4 {
                dst.put_u32(asn);
            } else {
                dst.put_u16(u16::try_from(asn).expect("4-byte ASN in 2-byte AS path"));
            }
        }
        encoded_len
    }

    fn encoded_len(&self) -> usize {
        2 + self.asns.len() * if self.as4 { 4 } else { 2 }
    }
}

/// BGP aggregator (RFC 4271 Section 5.1.7)
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Aggregator {
    pub asn: u16,
    pub ip: Ipv4Addr,
}

impl Component for Aggregator {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let asn = src.get_u16();
        let ip = Ipv4Addr::from_bytes(src)?;
        Ok(Self { asn, ip })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        dst.put_u16(self.asn);
        self.ip.to_bytes(dst) + 2 // 2 bytes for ASN
    }

    fn encoded_len(&self) -> usize {
        4 + 2
    }
}

/// BGP `MP_REACH_NLRI` (RFC 4760 Section 7)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: MpNextHop,
    pub nlri: Routes,
}

impl Component for MpReachNlri {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let afi = src.get_u16();
        let afi =
            Afi::try_from(afi).map_err(|_| crate::Error::InternalType("MP_REACH_NLRI AFI", afi))?;
        let safi = src.get_u8();
        let safi = Safi::try_from(safi)
            .map_err(|_| crate::Error::InternalType("MP_REACH_NLRI SAFI", u16::from(safi)))?;
        let nh_len = src.get_u8() as usize;
        let mut nh_src = src.split_to(nh_len);
        let next_hop = MpNextHop::from_bytes(&mut nh_src)?;
        let _ = src.get_u8(); // Reserved
        let nlri = Routes::from_bytes(src)?;
        Ok(Self {
            afi,
            safi,
            next_hop,
            nlri,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        dst.put_u16(self.afi as u16);
        len += 2;
        dst.put_u8(u8::try_from(self.safi as u16).expect("MP_REACH_NLRI SAFI out of range"));
        len += 1;
        dst.put_u8(
            u8::try_from(self.next_hop.encoded_len())
                .expect("MP_REACH_NLRI next hop length overflow"),
        );
        len += 1;
        len += self.next_hop.to_bytes(dst);
        dst.put_u8(0); // Reserved
        len += 1;
        len += self.nlri.to_bytes(dst);
        len
    }

    fn encoded_len(&self) -> usize {
        2 + 1 + 1 + self.next_hop.encoded_len() + 1 + self.nlri.encoded_len()
    }
}

/// Next hop for `MP_REACH_NLRI`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MpNextHop {
    Single(IpAddr),
    V6AndLL(Ipv6Addr, Ipv6Addr),
}

impl Component for MpNextHop {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        match src.remaining() {
            4 | 16 => Ok(Self::Single(IpAddr::from_bytes(src)?)),
            32 => {
                let v6local = Ipv6Addr::from_bytes(src)?;
                let v6ll = Ipv6Addr::from_bytes(src)?;
                Ok(Self::V6AndLL(v6local, v6ll))
            }
            _ => Err(crate::Error::InternalLength(
                "MP_NEXT_HOP",
                std::cmp::Ordering::Equal,
            )),
        }
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        match self {
            Self::Single(ip) => {
                ip.to_bytes(dst);
            }
            Self::V6AndLL(v6local, v6ll) => {
                v6local.to_bytes(dst);
                v6ll.to_bytes(dst);
            }
        }
        self.encoded_len()
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Single(IpAddr::V4(_)) => 4,
            Self::Single(IpAddr::V6(_)) => 16,
            Self::V6AndLL(_, _) => 32,
        }
    }
}

impl From<IpAddr> for MpNextHop {
    fn from(ip: IpAddr) -> Self {
        Self::Single(ip)
    }
}

/// BGP `MP_UNREACH_NLRI` (RFC 4760 Section 7)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn_routes: Routes,
}

impl Component for MpUnreachNlri {
    fn from_bytes(src: &mut Bytes) -> Result<Self, crate::Error> {
        let afi = src.get_u16();
        let afi = Afi::try_from(afi)
            .map_err(|_| crate::Error::InternalType("MP_UNREACH_NLRI AFI", afi))?;
        let safi = src.get_u8();
        let safi = Safi::try_from(safi)
            .map_err(|_| crate::Error::InternalType("MP_UNREACH_NLRI SAFI", u16::from(safi)))?;
        let withdrawn_routes = Routes::from_bytes(src)?;
        Ok(Self {
            afi,
            safi,
            withdrawn_routes,
        })
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        dst.put_u16(self.afi as u16);
        len += 2;
        dst.put_u8(u8::try_from(self.safi as u16).expect("MP_UNREACH_NLRI SAFI out of range"));
        len += 1;
        len += self.withdrawn_routes.to_bytes(dst);
        len
    }

    fn encoded_len(&self) -> usize {
        3 + self.withdrawn_routes.encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cidr::Cidr4, hex_to_bytes};

    #[test]
    fn test_origin() {
        let mut src = hex_to_bytes("40 01 01 00");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x40),
                data: Data::Origin(Origin::Igp),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_as2_aspath_wsh_1() {
        let mut src = hex_to_bytes("40 0204 0201 fd7d");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x40),
                data: Data::AsPath(AsPath(vec![AsSegment {
                    type_: AsSegmentType::AsSequence,
                    asns: vec![0xfd7d],
                    as4: false
                }])),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_as4_aspath_wsh_1() {
        let mut src = hex_to_bytes("40 02 0e 0203 fcde39d1 fcde3880 fcde3122");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x40),
                data: Data::AsPath(AsPath(vec![AsSegment {
                    type_: AsSegmentType::AsSequence,
                    asns: vec![0xfcde_39d1, 0xfcde_3880, 0xfcde_3122],
                    as4: true
                }])),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_next_hop() {
        let mut src = hex_to_bytes("40 03 04 7f000001");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x40),
                data: Data::NextHop(Ipv4Addr::new(127, 0, 0, 1)),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_multi_exit_disc_wsh_1() {
        let mut src = hex_to_bytes("80 04 04 00000000");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x80),
                data: Data::MultiExitDisc(0),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_as4path() {
        let mut src = hex_to_bytes("c0 11 06 0201 0000fd7d");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0xc0),
                data: Data::As4Path(AsPath(vec![AsSegment {
                    type_: AsSegmentType::AsSequence,
                    asns: vec![0xfd7d],
                    as4: true
                }])),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_mp_reach_nlri_wsh_1() {
        let mut src = hex_to_bytes("90 0e 002a
        0001 01 20 00000000000000000000000000000000 fe80000000000000000000000000abcd 0020 0a.7f.7f.7f");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x90),
                data: Data::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    next_hop: MpNextHop::V6AndLL(
                        "::".parse().unwrap(),
                        "fe80::abcd".parse().unwrap()
                    ),
                    nlri: Routes(vec![Cidr4::new(Ipv4Addr::new(10, 127, 127, 127), 32).into()])
                }),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_mp_unreach_nlri_wsh_1() {
        let mut src = hex_to_bytes("90 0f 0007 0001 01 18 ac.17.e3");
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0x90),
                data: Data::MpUnreachNlri(MpUnreachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    withdrawn_routes: Routes(vec![
                        Cidr4::new(Ipv4Addr::new(172, 23, 227, 0), 24).into()
                    ])
                }),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }

    #[test]
    fn test_other_large_community_wsh_1() {
        let mut src = hex_to_bytes(
            "c0 20 24fcde31ef0000007800000014fcde31ef0000008200000001fcde31ef0000008c00000035",
        );
        let saved = src.clone();
        let pa = Value::from_bytes(&mut src).unwrap();
        assert_eq!(
            pa,
            Value {
                flags: Flags(0xc0),
                data: Data::Unsupported(
                    0x20,
                    hex_to_bytes(
                        "fcde31ef0000007800000014fcde31ef0000008200000001fcde31ef0000008c00000035"
                    )
                ),
            }
        );
        let encoded_len = pa.encoded_len();
        let mut dst = bytes::BytesMut::new();
        pa.to_bytes(&mut dst);
        assert_eq!(dst, saved);
        assert_eq!(encoded_len, dst.len());
    }
}
