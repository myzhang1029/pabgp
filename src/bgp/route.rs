//! BGP route
//!
//! These structures do not contain information about the address family of
//! the route as they correspond to BGP's NLRI fields. To determine the address
//! family, the caller must know the context (BGP.nlri, MP_REACH_NLRI, etc).

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::cidr::{Cidr, Cidr4, Cidr6};
use super::endec::Component;
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
    pub prefix_len: u8,
    pub prefix: Bytes,
}

/// BGP routes
///
/// Corresponding to a compact list of CIDR blocks without a length field.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Routes(pub Vec<Value>);

impl Component for Routes {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, super::endec::Error> {
        let mut routes = Vec::new();
        while src.has_remaining() {
            let prefix_len = src.get_u8();
            let n_prefix_octets = n_prefix_octets(prefix_len);
            let prefix = src.split_to(n_prefix_octets);
            routes.push(Value { prefix_len, prefix });
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

    fn encoded_len(&self) -> usize {
        Self::slice_encoded_len(&self.0)
    }
}

impl Deref for Routes {
    type Target = Vec<Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Routes {
    /// Find the encoded size of a slice of routes
    fn slice_encoded_len(routes: &[Value]) -> usize {
        routes.iter().map(|r| 1 + r.prefix.len()).sum()
    }

    /// Find a set of split points for the given routes, such that each
    /// set of routes encodes to a size less than or equal to `allowed_size`.
    ///
    /// If no split is required, the result will be `vec![len]`.
    /// However, if the routes are too large to encode in the allowed size,
    /// the result will be an empty vector.
    pub fn split_routes_to_allowed_size_each(&self, allowed_size: usize) -> Vec<usize> {
        // The algorithm is to exponentially decrease the number of routes
        // to keep in each iteration to fit one set. For the next set, the
        // number of routes to keep is inherited from the previous set.
        // If later routes are shorter than the previous set, the algorithm
        // produces a suboptimal result.
        let len = self.len();
        let mut split_points = Vec::new();
        let mut start = 0;
        let mut to_keep_each = len;
        while start < self.len() {
            let mut end = len.min(start + to_keep_each);
            let mut encoded_len = Self::slice_encoded_len(&self[start..end]);
            while encoded_len > allowed_size {
                to_keep_each /= 2;
                if to_keep_each == 0 {
                    return Vec::new();
                }
                end = len.min(start + to_keep_each);
                encoded_len = Self::slice_encoded_len(&self[start..end]);
            }
            split_points.push(end);
            start += to_keep_each;
        }
        split_points
    }

    /// Similar to `split_routes_to_allowed_size_each`, but returns the
    /// left boundary of each split instead of the right boundary and
    /// reverses the order of the split points. This is useful for
    /// calling `Vec::split_off` without having to offset the split points.
    pub fn split_routes_to_allowed_size_rev(&self, allowed_size: usize) -> Vec<usize> {
        let mut split_points = self.split_routes_to_allowed_size_each(allowed_size);
        // Remove tail and add 0 and reverse in place
        split_points.pop();
        split_points.reverse();
        split_points.push(0);
        split_points
    }
}

impl<I, T> From<I> for Routes
where
    I: IntoIterator<Item = T>,
    T: Into<Value>,
{
    fn from(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

impl From<Cidr4> for Value {
    fn from(cidr: Cidr4) -> Self {
        let prefix_len = cidr.prefix_len;
        let n_prefix_octets = n_prefix_octets(prefix_len);
        let prefix = Bytes::copy_from_slice(&cidr.addr.octets()[..n_prefix_octets]);
        Self { prefix_len, prefix }
    }
}

impl From<Cidr6> for Value {
    fn from(cidr: Cidr6) -> Self {
        let prefix_len = cidr.prefix_len;
        let n_prefix_octets = n_prefix_octets(prefix_len);
        let prefix = Bytes::copy_from_slice(&cidr.addr.octets()[..n_prefix_octets]);
        Self { prefix_len, prefix }
    }
}

impl From<&Cidr4> for Value {
    fn from(cidr: &Cidr4) -> Self {
        // `Cidr4` implements `Copy`, so I don't understand why Rust is complaining
        Self::from(*cidr)
    }
}

impl From<&Cidr6> for Value {
    fn from(cidr: &Cidr6) -> Self {
        // `Cidr6` implements `Copy`, so I don't understand why Rust is complaining
        Self::from(*cidr)
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
    use crate::bgp::tests::hex_to_bytes;
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

    #[test]
    fn test_split_routes_to_allowed_size_each_1() {
        // Yes. This is the 44net IPIP mesh table at one point in time.
        let mut routesraw = hex_to_bytes(
            "1f 2c3f0102
            18 2c1407
            1d 2c3f07a0
            1b 2c3f1fe0
            1c 2c221100
            19 2c3f7f80
            1d 2c4c0018
            1d 2c384010
            20 2c3f002d
            1d 2c3c2900
            1d 2c3e0970
            1d 2c3f0878
            20 2c04261b
            1c 2c18ab70
            1d 2c3f08a0
            18 2c2e20
            1d 2c442a00
            20 2c3f000b
            1d 2c3f07c8
            1d 2c381a00
            1d 2c581040
            1d 2c4c0118
            18 2c142a
            1c 2c3f1310
            1b 2c448c00
            1d 2c387e00
            1c 2c210600
            18 2c7f08
            1d 2c3f0978
            1d 2c040a28
            1c 2c3f1160
            1c 2c080110
            20 2c2e000c
            1c 2c3f11c0
            18 2c4018
            19 2c3f8180
            1c 2c4c0b10
            18 2c18c2
            18 2c4818
            1c 2c3f1010
            1d 2c383e10
            1d 2c023200
            1a 2c3f3f80
            18 2c6684
            18 2c0e02
            1b 2c442900
            1b 2c3f20e0
            1c 2c3f12c0
            20 2c100901
            1d 2c3f0928
            18 2c4819
            1c 2c3f1110
            1d 2c383900
            1d 2c622108
            20 2c668381
            20 2c3f0039
            1d 2c3f08d8
            20 2c1200ba
            1d 2c5c0050
            18 2c2e80
            1b 2c3f1f40
            1c 2c3e09d0
            18 2c1425
            1c 2c3f1270
            1c 2c6462a0
            1b 2c401200
            1d 2c30be00
            1d 2c668710
            17 2c28a0
            1d 2c3f0900
            1d 2c381600
            1d 2c400c40
            1b 2c041020
            1d 2c3f0728
            1c 2c2401a0
            1d 2c0402a0
            1b 2c3f22a0
            1c 2c3f0f70
            1c 2c763900
            1d 2c5c0000
            1d 2c581100
            18 2c1405
            1c 2c048a00
            18 2c5a2c
            1c 2c3f1220
            1d 2c384020
            1b 2c100220
            1c 2c446600
            20 2c3f0042
            1a 2c3c4800",
        );
        let raw_len = routesraw.len();
        let routes = Routes::from_bytes(&mut routesraw).unwrap();
        for allowed_size in 1..=raw_len {
            let split_points = routes.split_routes_to_allowed_size_each(allowed_size);
            log::debug!("Allowed size: {allowed_size}, split points: {split_points:?}");
            // The algorithm is allowed to change, so we only check if the result is correct
            if allowed_size < 5 {
                // Won't fit even one route
                assert_eq!(split_points, Vec::new());
            } else if allowed_size == raw_len {
                assert_eq!(split_points, vec![routes.len()]);
            } else {
                let mut new_routes = Vec::new();
                let mut start = 0;
                for &end in &split_points {
                    let this_seg = &routes.0[start..end];
                    log::debug!("Split with {}..{}: len={}", start, end, this_seg.len());
                    assert!(Routes::slice_encoded_len(this_seg) <= allowed_size);
                    new_routes.extend_from_slice(&this_seg);
                    start = end;
                }
                assert_eq!(new_routes, routes.0);
            }
            let split_points_rev = routes.split_routes_to_allowed_size_rev(allowed_size);
            // Compare to the reverse of the forward split points after removing [0] and prepending 0
            let should_be: Vec<usize> = split_points
                .iter()
                .rev()
                .skip(1)
                .copied()
                .chain(std::iter::once(0))
                .collect();
            assert_eq!(split_points_rev, should_be);
        }
    }
}
