//! Simple CIDR block representation

// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A IPv4 CIDR block
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cidr4 {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl fmt::Display for Cidr4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}
impl Cidr4 {
    #[must_use]
    pub const fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// Create a new CIDR block from a starting address and the number of hosts
    ///
    /// # Panics
    /// Will panic if the number of hosts is more than 2^32
    #[must_use]
    pub fn from_num_hosts(start: Ipv4Addr, num_hosts: u32) -> Vec<Self> {
        let mut cidrs = Vec::with_capacity(num_hosts.count_ones() as usize);
        let mut current_addr = u32::from(start);
        let mut remaining_hosts = num_hosts;
        while remaining_hosts > 0 {
            let biggest_netbits = remaining_hosts.ilog2();
            let netsize = 1 << biggest_netbits;
            let prefix_len = 32 - biggest_netbits;
            if current_addr % netsize != 0 {
                log::error!(
                    "Network address {current_addr} is not aligned to block size {netsize}"
                );
            }
            // This unwrap never fails because biggest_netbits is at most 32
            let cidr = Self::new(
                Ipv4Addr::from(current_addr),
                u8::try_from(prefix_len).unwrap(),
            );
            cidrs.push(cidr);
            current_addr += netsize;
            remaining_hosts -= netsize;
        }
        cidrs
    }
}

/// A IPv6 CIDR block
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cidr6 {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

impl fmt::Display for Cidr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Cidr6 {
    #[must_use]
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }
}

/// A CIDR block
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Cidr {
    V4(Cidr4),
    V6(Cidr6),
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(cidr) => write!(f, "{cidr}"),
            Self::V6(cidr) => write!(f, "{cidr}"),
        }
    }
}

impl Cidr {
    #[must_use]
    pub const fn into_parts(self) -> (IpAddr, u8) {
        match self {
            Self::V4(cidr) => (IpAddr::V4(cidr.addr), cidr.prefix_len),
            Self::V6(cidr) => (IpAddr::V6(cidr.addr), cidr.prefix_len),
        }
    }
}
