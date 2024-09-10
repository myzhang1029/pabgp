//! BGP session

// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::rirstat::DatabaseDiff;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use pabgp::capability::{self, Afi, Capabilities, CapabilitiesBuilder, Safi};
use pabgp::path::{AsSegmentType, Origin};
use pabgp::route::Routes;
use pabgp::{
    Codec, Error as PacketError, Message, Notification, NotificationErrorCode, Open,
    OpenMessageErrorSubcode, UpdateBuilder, BGP_VERSION,
};
use tokio::net::{tcp, TcpStream};
use tokio::sync::broadcast;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid version")]
    InvalidVersion,
    #[error("peer sent an unexpected message")]
    UnexpectedMessage,
    #[error("peer sent a notification: {:?}({}), data: {:?}", .0.error_code, .0.error_subcode, .0.data)]
    PeerNotification(pabgp::Notification),
}

/// A simple passive BGP speaker
pub struct Feeder {
    init_ipv4_routes: Option<Routes>,
    init_ipv6_routes: Option<Routes>,
    recv_updates: broadcast::Receiver<DatabaseDiff>,
    local_as: u32,
    local_id: std::net::Ipv4Addr,
    next_hop: std::net::IpAddr,
    rx: FramedRead<tcp::OwnedReadHalf, Codec>,
    tx: FramedWrite<tcp::OwnedWriteHalf, Codec>,
    peer_hold_time: Option<u16>,
    peer_caps: Capabilities,
    // Default to true unless the peer does not support it
    enable_mp_bgp: bool,
}

impl Feeder {
    pub fn new(
        init_ipv4_routes: Option<Routes>,
        init_ipv6_routes: Option<Routes>,
        recv_updates: broadcast::Receiver<DatabaseDiff>,
        socket: TcpStream,
        local_as: u32,
        local_id: std::net::Ipv4Addr,
        next_hop: std::net::IpAddr,
    ) -> Self {
        let (rx, tx) = socket.into_split();
        let codec = Codec;
        let rx = FramedRead::new(rx, codec);
        let tx = FramedWrite::new(tx, codec);
        Self {
            init_ipv4_routes,
            init_ipv6_routes,
            recv_updates,
            local_as,
            local_id,
            next_hop,
            rx,
            tx,
            peer_hold_time: None,
            peer_caps: Capabilities::default(),
            enable_mp_bgp: true,
        }
    }

    pub async fn idle(&mut self) -> Result<(), Error> {
        log::debug!("Idle state");
        let packet = self.rx.next().await.ok_or(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF",
        )))??;
        if let Message::Open(open) = packet {
            log::trace!("Peer OPEN message: {open:?}");
            let peer_version = open.version;
            let peer_asn = open.asn;
            let peer_hold_time = open.hold_time;
            let peer_bgp_id = open.bgp_id;
            let peer_opt_params = open.opt_params;
            log::info!("Received OPEN message from peer (ASN: {peer_asn}, BGP ID: {peer_bgp_id})");
            self.connect(
                peer_version,
                peer_asn,
                peer_hold_time,
                peer_bgp_id,
                peer_opt_params,
            )
            .await
        } else {
            log::warn!("Received non-OPEN message from peer");
            Err(Error::UnexpectedMessage)
        }
    }

    fn parse_peer_capabilities(&mut self) {
        for cap in self.peer_caps.iter() {
            log::debug!("Peer advertised capability: {cap:?}");
        }
        // Whether the peer supports passing routes in a MP_* path attribute
        self.enable_mp_bgp =
            self.peer_caps.has_mp_ipv4_unicast() || self.peer_caps.has_mp_ipv6_unicast();
        if !self
            .peer_caps
            .has_extended_next_hop(Afi::Ipv6, Safi::Unicast, Afi::Ipv4)
            && self.next_hop.is_ipv4()
        {
            log::warn!("Peer does not support IPv4 next-hop in IPv6 routes");
        }
        if !self
            .peer_caps
            .has_extended_next_hop(Afi::Ipv4, Safi::Unicast, Afi::Ipv6)
            && self.next_hop.is_ipv6()
        {
            log::warn!("Peer does not support IPv6 next-hop in IPv4 routes");
        }
    }

    async fn connect(
        &mut self,
        peer_version: u8,
        peer_asn: u16,
        peer_hold_time: u16,
        peer_bgp_id: std::net::Ipv4Addr,
        mut peer_opt_params: capability::OptionalParameters,
    ) -> Result<(), Error> {
        log::debug!("Connect state");
        log::info!("Connection from peer (ASN: {peer_asn}, BGP ID: {peer_bgp_id})");
        if peer_version != BGP_VERSION {
            log::warn!("Peer version mismatch: expected {BGP_VERSION}, got {peer_version}");
            let notification = Message::Notification(Notification::new(
                NotificationErrorCode::OpenMessageError,
                OpenMessageErrorSubcode::UnsupportedVersionNumber as u8,
                Bytes::new(),
            ));
            // Send notification
            self.tx.feed(notification).await?;
            // Transition to Idle
            return Err(Error::InvalidVersion);
        }
        // Respond with OPEN
        let capabilities = CapabilitiesBuilder::new()
            .mp_ipv4_unicast()
            .mp_ipv6_unicast()
            .enh_ipv4_over_ipv6()
            .four_octet_as_number_if_needed(self.local_as)
            .build();
        // Make sure the peer hold time is longer than or equal to our hold time,
        // so we don't have to worry about sending keepalives before they do it
        // for us. (This is cheating, but it's a simple implementation)
        let open = Message::Open(Open::new_easy(
            self.local_as,
            180.min(peer_hold_time),
            self.local_id,
            capabilities,
        ));
        self.peer_hold_time = Some(peer_hold_time);
        while let Some(op) = peer_opt_params.0.pop() {
            #[allow(irrefutable_let_patterns)]
            if let capability::OptionalParameterValue::Capabilities(caps) = op {
                self.peer_caps = caps;
            }
            self.parse_peer_capabilities();
        }
        self.tx.feed(open).await?;
        self.tx.flush().await?;
        log::info!("Sent OPEN message to peer");
        // Transition to OpenSent
        self.open_sent_confirm().await
    }

    async fn open_sent_confirm(&mut self) -> Result<(), Error> {
        log::debug!("OpenSent state");
        let packet = self.rx.next().await.ok_or(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF",
        )))??;
        match packet {
            Message::Keepalive => {
                log::info!("Received KEEPALIVE message from peer");
                log::debug!("OpenConfirm state");
                // Just send the exact same message back
                self.tx.feed(packet).await?;
                self.tx.flush().await?;
                // Transition to Established
                self.established().await
            }
            Message::Notification(notification) => {
                log::warn!(
                    "Received NOTIFICATION message from peer: {:?} {}",
                    notification.error_code,
                    notification.error_subcode
                );
                // Transition to Idle
                Err(Error::PeerNotification(notification))
            }
            _ => {
                log::warn!("Received non-KEEPALIVE message from peer");
                Err(Error::UnexpectedMessage)
            }
        }
    }

    async fn handle_peer_packet(&mut self, packet: Message) -> Result<(), Error> {
        match packet {
            Message::Keepalive => {
                log::debug!("Received KEEPALIVE message from peer");
                // Just send the exact same message back
                self.tx.feed(packet).await?;
                self.tx.flush().await?;
            }
            Message::Notification(notification) => {
                log::warn!(
                    "Received NOTIFICATION message from peer: {:?} {}",
                    notification.error_code,
                    notification.error_subcode
                );
                // Transition to Idle
                return Err(Error::PeerNotification(notification));
            }
            Message::Update(update) => {
                log::debug!("Received UPDATE message from peer.");
                log::debug!("Peer withdrew {} routes", update.withdrawn_routes.len());
                log::debug!("Peer added {} OLD BGP routes", update.nlri.len());
                log::debug!(
                    "Peer packet contains {} path attributes",
                    update.path_attributes.len()
                );
                log::debug!("No further processing implemented");
            }
            Message::Open(_) => {
                log::warn!("Received unexpected OPEN message from peer: {:?}", packet);
            }
        }
        Ok(())
    }

    async fn send_initial_updates(&mut self) -> Result<(), Error> {
        let packets = UpdateBuilder::new(self.enable_mp_bgp)
            .set_next_hop(self.next_hop.into())
            .set_origin(Origin::Igp)
            .set_as_path(AsSegmentType::AsSequence, vec![self.local_as])
            .add_ipv4_routes(
                self.init_ipv4_routes
                    .take()
                    .expect("Initial IPv4 routes not set"),
            )
            .add_ipv6_routes(
                self.init_ipv6_routes
                    .take()
                    .expect("Initial IPv6 routes not set"),
            )
            .build()?;
        for packet in packets {
            log::trace!("Sending initial route packet: {packet:?}");
            self.tx.feed(Message::Update(packet)).await?;
        }
        self.tx.flush().await?;
        log::info!("Sent initial routes to peer");
        Ok(())
    }

    async fn established(&mut self) -> Result<(), Error> {
        log::debug!("Established state");
        log::info!("Peer connection established");
        self.send_initial_updates().await?;
        loop {
            tokio::select! {
                diffres = self.recv_updates.recv() => {
                    log::info!("Received database update");
                    let diff = diffres.expect("Database updater task exited");
                    let new_ipv4: pabgp::route::Routes = diff.new_ipv4.values().flatten().into();
                    let new_ipv6: pabgp::route::Routes = diff.new_ipv6.values().flatten().into();
                    let withdrawn_ipv4: pabgp::route::Routes = diff.withdrawn_ipv4.values().flatten().into();
                    let withdrawn_ipv6: pabgp::route::Routes = diff.withdrawn_ipv6.values().flatten().into();
                    log::info!(
                        "Database update: {} new IPv4, {} new IPv6, {} withdrawn IPv4, {} withdrawn IPv6",
                        new_ipv4.len(),
                        new_ipv6.len(),
                        withdrawn_ipv4.len(),
                        withdrawn_ipv6.len()
                    );
                    let packets = UpdateBuilder::new(self.enable_mp_bgp)
                        .set_next_hop(self.next_hop.into())
                        .set_origin(Origin::Igp)
                        .set_as_path(AsSegmentType::AsSequence, vec![self.local_as])
                        .add_ipv4_routes(new_ipv4)
                        .add_ipv6_routes(new_ipv6)
                        .withdraw_ipv4_routes(withdrawn_ipv4)
                        .withdraw_ipv6_routes(withdrawn_ipv6)
                        .build()?;
                    for packet in packets {
                        self.tx.feed(Message::Update(packet)).await?;
                    }
                    self.tx.flush().await?;
                    log::info!("Sent database update to peer");
                }
                packet = self.rx.next() => {
                    let packet = packet.ok_or(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF",
                    )))??;
                    self.handle_peer_packet(packet).await?;
                }
            }
        }
    }
}
