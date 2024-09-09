//! BGP session

// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::bgp::capability::{self, Capabilities, CapabilitiesBuilder};
use crate::bgp::{
    Codec, Error as PacketError, Message, Notification, NotificationErrorCode, Open,
    OpenMessageErrorSubcode, BGP_VERSION,
};
use crate::rirstat::{Database, DatabaseDiff};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
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
    PeerNotification(crate::bgp::Notification),
}

pub struct Feeder {
    init_db: Option<Database>,
    recv_updates: broadcast::Receiver<DatabaseDiff>,
    local_as: u32,
    local_id: std::net::Ipv4Addr,
    next_hop: std::net::IpAddr,
    rx: FramedRead<tcp::OwnedReadHalf, Codec>,
    tx: FramedWrite<tcp::OwnedWriteHalf, Codec>,
    peer_hold_time: Option<u16>,
    peer_caps: Capabilities,
}

impl Feeder {
    pub fn new(
        init_db: Database,
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
            init_db: Some(init_db),
            recv_updates,
            local_as,
            local_id,
            next_hop,
            rx,
            tx,
            peer_hold_time: None,
            peer_caps: Capabilities::default(),
        }
    }

    pub async fn idle(&mut self) -> Result<(), Error> {
        // State = Idle
        let packet = self.rx.next().await.ok_or(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF",
        )))??;
        if let Message::Open(open) = packet {
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

    async fn connect(
        &mut self,
        peer_version: u8,
        peer_asn: u16,
        peer_hold_time: u16,
        peer_bgp_id: std::net::Ipv4Addr,
        mut peer_opt_params: capability::OptionalParameters,
    ) -> Result<(), Error> {
        // State = Connect
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
        let open = Message::Open(Open::new_easy(
            self.local_as,
            180,
            self.local_id,
            capabilities,
        ));
        self.peer_hold_time = Some(peer_hold_time);
        while let Some(op) = peer_opt_params.0.pop() {
            #[allow(irrefutable_let_patterns)]
            if let capability::OptionalParameterValue::Capabilities(caps) = op {
                self.peer_caps = caps;
            }
        }
        self.tx.feed(open).await?;
        self.tx.flush().await?;
        log::info!("Sent OPEN message to peer");
        // Transition to OpenSent
        self.open_sent_confirm().await
    }

    async fn open_sent_confirm(&mut self) -> Result<(), Error> {
        // State = OpenSent
        let packet = self.rx.next().await.ok_or(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF",
        )))??;
        match packet {
            Message::Keepalive => {
                log::info!("Received KEEPALIVE message from peer");
                // State = OpenConfirm
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
                log::info!("Received KEEPALIVE message from peer");
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
                log::info!("Received UPDATE message from peer.");
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

    async fn established(&mut self) -> Result<(), Error> {
        // State = Established
        loop {
            tokio::select! {
                _ = self.recv_updates.recv() => {
                    // Send UPDATE
                    // TODO: implement
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
