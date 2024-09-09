//! BGP route

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::endec::Component;
use crate::cidr::{Cidr, Cidr4, Cidr6};
use bytes::{Buf, BufMut, Bytes};
use std::ops::Deref;

/// Compute the number of prefix octets from the prefix length
fn n_prefix_octets(prefix_len: u8) -> usize {
    #[allow(clippy::verbose_bit_mask)]
    let result = if prefix_len & 0x07 == 0 {
        prefix_len >> 3
    } else {
        (prefix_len >> 3) + 1
    };
    usize::from(result)
}

/// BGP route CIDR blocks
///
/// Corresponding to a compact representation of a u8 prefix length and the
/// minimum number of octets to represent the prefix.
#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    pub prefix: Bytes,
    pub prefix_len: u8,
}

/// BGP routes
///
/// Corresponding to a compact list of CIDR blocks without a length field.
#[derive(Clone, Debug, PartialEq)]
pub struct Routes(pub Vec<Value>);

impl Component for Routes {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, super::endec::Error> {
        let mut routes = Vec::new();
        while src.has_remaining() {
            let prefix_len = src.get_u8();
            let n_prefix_octets = n_prefix_octets(prefix_len);
            let prefix = src.split_to(n_prefix_octets);
            routes.push(Value { prefix, prefix_len });
        }
        Ok(Self(routes))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        let mut len = 0;
        for route in self.0 {
            dst.put_u8(route.prefix_len);
            dst.put_slice(&route.prefix);
            len += 1 + route.prefix.len();
        }
        len
    }
}

impl Deref for Routes {
    type Target = Vec<Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Cidr4> for Value {
    fn from(cidr: Cidr4) -> Self {
        let prefix_len = cidr.prefix_len;
        let n_prefix_octets = n_prefix_octets(prefix_len);
        let prefix = Bytes::copy_from_slice(&cidr.addr.octets()[..n_prefix_octets]);
        Self { prefix, prefix_len }
    }
}

impl From<Cidr6> for Value {
    fn from(cidr: Cidr6) -> Self {
        let prefix_len = cidr.prefix_len;
        let n_prefix_octets = n_prefix_octets(prefix_len);
        let prefix = Bytes::copy_from_slice(&cidr.addr.octets()[..n_prefix_octets]);
        Self { prefix, prefix_len }
    }
}

impl From<Cidr> for Value {
    fn from(cidr: Cidr) -> Self {
        match cidr {
            Cidr::V4(cidr) => cidr.into(),
            Cidr::V6(cidr) => cidr.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::packet::tests::hex_to_bytes;
    use bytes::BytesMut;

    #[test]
    fn test_convert_cidr_to_route_on_boundary() {
        let cidr4 = Cidr4 {
            addr: "127.0.0.0".parse().unwrap(),
            prefix_len: 8,
        };
        let route4 = Value::from(cidr4);
        assert_eq!(route4.prefix, hex_to_bytes("7f"));
        assert_eq!(route4.prefix_len, 8);

        let cidr6 = Cidr6 {
            addr: "fdc7:3c9d:ff31:7::".parse().unwrap(),
            prefix_len: 64,
        };
        let route6 = Value::from(cidr6);
        assert_eq!(route6.prefix, hex_to_bytes("fdc7:3c9d:ff31:0007"));
        assert_eq!(route6.prefix_len, 64);
    }

    #[test]
    fn test_convert_cidr_to_route_off_boundary() {
        let cidr4 = Cidr4 {
            addr: "172.24.0.0".parse().unwrap(),
            prefix_len: 12,
        };
        let route4 = Value::from(cidr4);
        assert_eq!(route4.prefix, hex_to_bytes("ac18"));
        assert_eq!(route4.prefix_len, 12);

        let cidr6 = Cidr6 {
            addr: "fdc0::f000:0".parse().unwrap(),
            prefix_len: 110,
        };
        let route6 = Value::from(cidr6);
        assert_eq!(
            route6.prefix,
            hex_to_bytes("fdc0:0000:0000:0000.0000:0000:f000")
        );
        assert_eq!(route6.prefix_len, 110);
    }

    #[test]
    fn test_mpbgp_routes() {
        let routes_bytes = hex_to_bytes(
            "
        40 fdc7:3c9d:ff31:0007
        40 fdc7:3c9d:ff31:0003
        40 fdc7:3c9d:ff31:000f
        40 fdc7:3c9d:ff31:000b
        40 fdc7:3c9d:b889:a272
        40 fdc7:3c9d:ff31:fb02",
        );
        let routes = Routes::from_bytes(&mut routes_bytes.clone()).unwrap();
        assert_eq!(routes.0.len(), 6);
        assert_eq!(
            routes.0[0],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:ff31:7::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            routes.0[1],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:ff31:3::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            routes.0[2],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:ff31:f::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            routes.0[3],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:ff31:b::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            routes.0[4],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:b889:a272::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            routes.0[5],
            Value::from(Cidr6 {
                addr: "fdc7:3c9d:ff31:fb02::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        let mut bytes = BytesMut::new();
        routes.to_bytes(&mut bytes);
        assert_eq!(bytes.freeze(), routes_bytes);
    }

    #[test]
    fn test_routesv4() {
        let routes_bytes = hex_to_bytes(
            "
        18 cb1441
        0f 31d0
        16 2d7a5c
        11 2abb80
        16 ca4d5c
        14 65cbb0
        ",
        );
        let routes = Routes::from_bytes(&mut routes_bytes.clone()).unwrap();
        assert_eq!(routes.0.len(), 6);
        assert_eq!(
            routes.0[0],
            Value::from(Cidr4 {
                addr: "203.20.65.0".parse().unwrap(),
                prefix_len: 24
            })
        );
        assert_eq!(
            routes.0[1],
            Value::from(Cidr4 {
                addr: "49.208.0.0".parse().unwrap(),
                prefix_len: 15
            })
        );
        assert_eq!(
            routes.0[2],
            Value::from(Cidr4 {
                addr: "45.122.92.0".parse().unwrap(),
                prefix_len: 22
            })
        );
        assert_eq!(
            routes.0[3],
            Value::from(Cidr4 {
                addr: "42.187.128.0".parse().unwrap(),
                prefix_len: 17
            })
        );
        assert_eq!(
            routes.0[4],
            Value::from(Cidr4 {
                addr: "202.77.92.0".parse().unwrap(),
                prefix_len: 22
            })
        );
        assert_eq!(
            routes.0[5],
            Value::from(Cidr4 {
                addr: "101.203.176.0".parse().unwrap(),
                prefix_len: 20
            })
        );
        let mut bytes = BytesMut::new();
        routes.to_bytes(&mut bytes);
        assert_eq!(bytes.freeze(), routes_bytes);
    }
}
