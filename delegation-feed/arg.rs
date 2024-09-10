//! Command line arguments parsing.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::rirstat::rirbase::CountrySpec;
use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
pub struct DelegationFeed {
    /// Our AS number (supports 4-byte AS number)
    #[arg(required_unless_present = "dry_run", default_value = "0")]
    pub local_as: u32,
    /// Our BGP router ID
    #[arg(required_unless_present = "dry_run", default_value = "0.0.0.0")]
    pub local_id: Ipv4Addr,
    /// Next hop for delegated IPv4 prefixes
    ///
    /// If both IPv4 and IPv6 prefixes are enabled, the peer is required to
    /// support MP-BGP and Extended Next Hop.
    ///
    /// Defaults to the local ID if not specified.
    #[arg(short = 'n', long)]
    pub next_hop: Option<IpAddr>,
    /// BGP session listen address
    #[arg(short = 'l', long, default_value = "::")]
    pub listen_addr: IpAddr,
    /// BGP session listen port
    #[arg(short = 'p', long, default_value = "179")]
    pub listen_port: u16,
    /// Whether to parse and advertise IPv4 prefixes
    #[arg(short = '4', long)]
    pub enable_ipv4: bool,
    /// Whether to parse and advertise IPv6 prefixes
    #[arg(short = '6', long)]
    pub enable_ipv6: bool,
    /// Interval in minutes to update the database
    #[arg(short = 'u', long, default_value = "60")]
    pub update_interval: u64,
    /// Countries of which prefixes are advertised
    pub countries: Vec<CountrySpec>,
    /// Verbose mode
    #[arg(short = 'v', long)]
    pub verbose: bool,
    /// Dry-run mode: download, parse, and print the routes, then exit
    #[arg(short = 'i', long)]
    pub dry_run: bool,
}
