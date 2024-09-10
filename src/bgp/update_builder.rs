//! Build UPDATE messages.

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::capability::Afi;
use super::cidr::Cidr;
use super::endec::{Component, Error};
use super::path::{self, AsPath, AsSegment, AsSegmentType, MpNextHop, Origin, PathAttributes};
use super::route::Routes;
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq)]
/// Builder for UPDATE messages.
pub struct UpdateBuilder {
    pub withdrawn_ipv4_routes: Routes,
    pub withdrawn_ipv6_routes: Routes,
    pub nlri_ipv4_routes: Routes,
    pub nlri_ipv6_routes: Routes,
    pub origin: Option<Origin>,
    pub as_path: AsPath,
    pub next_hop: Option<MpNextHop>,
    pub other_path_attrs: PathAttributes,
    pub enable_mp_bgp: bool,
}

impl UpdateBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(enable_mp_bgp: bool) -> Self {
        Self {
            enable_mp_bgp,
            ..Default::default()
        }
    }

    /// Withdraw some IPv4 routes.
    #[must_use]
    pub fn withdraw_ipv4_routes(mut self, routes: Routes) -> Self {
        self.withdrawn_ipv4_routes = routes;
        self
    }

    /// Withdraw some IPv6 routes.
    #[must_use]
    pub fn withdraw_ipv6_routes(mut self, routes: Routes) -> Self {
        self.withdrawn_ipv6_routes = routes;
        self
    }

    /// Withdraw a single route.
    #[must_use]
    pub fn withdraw_route(mut self, route: Cidr) -> Self {
        match route {
            Cidr::V4(route) => self.withdrawn_ipv4_routes.0.push(route.into()),
            Cidr::V6(route) => self.withdrawn_ipv6_routes.0.push(route.into()),
        }
        self
    }

    /// Add some IPv4 routes.
    #[must_use]
    pub fn add_ipv4_routes(mut self, routes: Routes) -> Self {
        self.nlri_ipv4_routes = routes;
        self
    }

    /// Add some IPv6 routes.
    #[must_use]
    pub fn add_ipv6_routes(mut self, routes: Routes) -> Self {
        self.nlri_ipv6_routes = routes;
        self
    }

    /// Add a single route.
    #[must_use]
    pub fn add_route(mut self, route: Cidr) -> Self {
        match route {
            Cidr::V4(route) => self.nlri_ipv4_routes.0.push(route.into()),
            Cidr::V6(route) => self.nlri_ipv6_routes.0.push(route.into()),
        }
        self
    }

    /// Set the origin.
    #[must_use]
    pub fn set_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Add an AS path segment.
    #[must_use]
    pub fn set_as_path(mut self, type_: AsSegmentType, asns: Vec<u32>) -> Self {
        let as4 = asns.iter().any(|&asn| asn > u32::from(u16::MAX));
        let segment = AsSegment { type_, asns, as4 };
        self.as_path.0.push(segment);
        self
    }

    /// Set the next hop.
    #[must_use]
    pub fn set_next_hop(mut self, next_hop: MpNextHop) -> Self {
        self.next_hop = Some(next_hop);
        self
    }

    /// Add a path attribute.
    #[must_use]
    pub fn path_attribute(mut self, attr: path::Value) -> Self {
        self.other_path_attrs.0.push(attr);
        self
    }

    /// Find out how to represent the next hop. If MP-BGP is not enabled,
    /// the next hop will be added to the path attributes.
    ///
    /// After this method is called, if no next hop is set, it means that
    /// NLRI components are empty and no next hop is needed.
    fn check_next_hop(&mut self) -> Result<(), Error> {
        if let Some(next_hop) = &self.next_hop {
            if self.enable_mp_bgp {
                Ok(())
            } else if let MpNextHop::Single(IpAddr::V4(addr)) = next_hop {
                self.other_path_attrs.0.push(path::Value {
                    flags: path::Flags::WELL_KNOWN_COMPLETE,
                    data: path::Data::NextHop(*addr),
                });
                Ok(())
            } else {
                Err(Error::NoMpBgp)
            }
        } else if !self.nlri_ipv6_routes.is_empty() || !self.withdrawn_ipv6_routes.is_empty() {
            Err(Error::NoNextHop)
        } else {
            Ok(())
        }
    }

    /// Make an MP_UNREACH_NLRI path attribute from a list of routes.
    fn make_mp_unreach_nlri(routes: Routes, afi: Afi) -> path::Value {
        let mp_unreach_nlri = path::MpUnreachNlri {
            afi,
            safi: super::Safi::Unicast,
            withdrawn_routes: routes,
        };
        path::Value {
            flags: path::Flags::OPTIONAL_TRANSITIVE_EXTENDED,
            data: path::Data::MpUnreachNlri(mp_unreach_nlri),
        }
    }

    /// Make an MP_REACH_NLRI path attribute from a list of routes.
    fn make_mp_reach_nlri(routes: Routes, afi: Afi, next_hop: MpNextHop) -> path::Value {
        let mp_reach_nlri = path::MpReachNlri {
            afi,
            safi: super::Safi::Unicast,
            next_hop,
            nlri: routes,
        };
        path::Value {
            flags: path::Flags::OPTIONAL_TRANSITIVE_EXTENDED,
            data: path::Data::MpReachNlri(mp_reach_nlri),
        }
    }

    /// Make an MP_UNREACH UPDATE message from routes split into smaller chunks.
    fn make_mp_unreach_update(
        all_withdrawn_routes: Routes,
        afi: Afi,
        allowed_size: usize,
        common_path_attributes: &PathAttributes,
        updates: &mut Vec<super::Update>,
    ) {
        let route_splits = all_withdrawn_routes.split_routes_to_allowed_size_rev(allowed_size);
        let mut leftover = all_withdrawn_routes.0;
        for end in route_splits {
            let withdrawn_routes = leftover.split_off(end);
            let mut this_path_attributes = common_path_attributes.clone();
            this_path_attributes
                .0
                .push(Self::make_mp_unreach_nlri(withdrawn_routes.into(), afi));
            updates.push(super::Update {
                withdrawn_routes: Routes::default(),
                path_attributes: this_path_attributes,
                nlri: Routes::default(),
            });
        }
    }

    /// Make an MP_REACH UPDATE message from routes split into smaller chunks.
    fn make_mp_reach_update(
        all_nlri_routes: Routes,
        afi: Afi,
        allowed_size: usize,
        common_path_attributes: &PathAttributes,
        next_hop: MpNextHop,
        updates: &mut Vec<super::Update>,
    ) {
        let route_splits = all_nlri_routes.split_routes_to_allowed_size_rev(allowed_size);
        let mut leftover = all_nlri_routes.0;
        for end in route_splits {
            let nlri_routes = leftover.split_off(end);
            let mut this_path_attributes = common_path_attributes.clone();
            this_path_attributes.0.push(Self::make_mp_reach_nlri(
                nlri_routes.into(),
                afi,
                next_hop,
            ));
            updates.push(super::Update {
                withdrawn_routes: Routes::default(),
                path_attributes: this_path_attributes,
                nlri: Routes::default(),
            });
        }
    }

    /// Build one or more UPDATE messages depending on the size of routes.
    pub fn build(mut self) -> Result<Vec<super::Update>, Error> {
        // The algorithm is quite simple and not very efficient.
        self.check_next_hop()?;
        let Self {
            withdrawn_ipv4_routes,
            withdrawn_ipv6_routes,
            nlri_ipv4_routes,
            nlri_ipv6_routes,
            origin,
            as_path,
            next_hop,
            other_path_attrs: mut small_attrs,
            enable_mp_bgp,
        } = self;
        // Prepare path attributes that are common for all UPDATE messages
        if let Some(origin) = origin {
            let pa = path::Value {
                flags: path::Flags::WELL_KNOWN_COMPLETE,
                data: path::Data::Origin(origin),
            };
            small_attrs.0.push(pa);
        }
        small_attrs.0.push(path::Value {
            flags: path::Flags::WELL_KNOWN_COMPLETE,
            data: path::Data::AsPath(as_path),
        });
        // Split the routes into smaller chunks and pack them into UPDATE messages
        let mut updates = Vec::new();
        if enable_mp_bgp {
            // First send withdrawn routes
            let remaining_size = 4096 - 19 - 4 - 3 - small_attrs.encoded_len(); // 4096 - BGP header - UPDATE header - MP_UNREACH_NLRI header
            Self::make_mp_unreach_update(
                withdrawn_ipv4_routes,
                Afi::Ipv4,
                remaining_size,
                &small_attrs,
                &mut updates,
            );
            Self::make_mp_unreach_update(
                withdrawn_ipv6_routes,
                Afi::Ipv6,
                remaining_size,
                &small_attrs,
                &mut updates,
            );
            // Then send NLRI
            if let Some(next_hop) = next_hop {
                let remaining_size =
                    4096 - 19 - 4 - 4 - next_hop.encoded_len() - small_attrs.encoded_len(); // 4096 - BGP header - UPDATE header - MP_REACH_NLRI header - MP_NEXT_HOP
                Self::make_mp_reach_update(
                    nlri_ipv4_routes,
                    Afi::Ipv4,
                    remaining_size,
                    &small_attrs,
                    next_hop,
                    &mut updates,
                );
                Self::make_mp_reach_update(
                    nlri_ipv6_routes,
                    Afi::Ipv6,
                    remaining_size,
                    &small_attrs,
                    next_hop,
                    &mut updates,
                );
            }
            // Else: `check_next_hop` ensures that there are no NLRI components
        } else {
            // Just IPv4 stuff for vanilla BGP-4
            let remaining_size = 4096 - 19 - 4 - small_attrs.encoded_len(); // 4096 - BGP header - UPDATE header
                                                                            // First send withdrawn routes
            let route_splits =
                withdrawn_ipv4_routes.split_routes_to_allowed_size_rev(remaining_size);
            let mut leftover = withdrawn_ipv4_routes.0;
            for end in route_splits {
                let withdrawn_routes = leftover.split_off(end);
                updates.push(super::Update {
                    withdrawn_routes: withdrawn_routes.into(),
                    path_attributes: small_attrs.clone(),
                    nlri: Routes::default(),
                });
            }
            // Then send NLRI
            if let Some(MpNextHop::Single(IpAddr::V4(next_hop))) = next_hop {
                let remaining_size = remaining_size - 4 - 3; // NEXT_HOP path attribute
                let route_splits =
                    nlri_ipv4_routes.split_routes_to_allowed_size_rev(remaining_size);
                let mut leftover = nlri_ipv4_routes.0;
                small_attrs.0.push(path::Value {
                    flags: path::Flags::WELL_KNOWN_COMPLETE,
                    data: path::Data::NextHop(next_hop),
                });
                for end in route_splits {
                    let nlri_routes = leftover.split_off(end);
                    updates.push(super::Update {
                        withdrawn_routes: Routes::default(),
                        path_attributes: small_attrs.clone(),
                        nlri: nlri_routes.into(),
                    });
                }
            }
        }
        Ok(updates)
    }
}
