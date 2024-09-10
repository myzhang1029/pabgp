//! BGP packet encoding and decoding

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::Error;
#[cfg(feature = "tokio-endec")]
use super::{Message, Notification, Open, Update};
use bytes::{Buf, BufMut};
use enum_primitive_derive::Primitive;
#[cfg(feature = "tokio-endec")]
use num_traits::FromPrimitive;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature = "tokio-endec")]
use tokio_util::codec::{Decoder, Encoder};

/// BGP packet encoder
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "tokio-endec")]
pub struct BgpCodec;

#[cfg(feature = "tokio-endec")]
impl Decoder for BgpCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < crate::MARKER.len() + 2 {
            // Marker + length
            return Ok(None);
        }
        let length = u16::from_be_bytes([src[16], src[17]]) as usize;
        if src.len() < length {
            return Ok(None);
        }
        // Now the packet is supposed to be complete and let's use the Buf methods
        // to avoid manual indexing.
        let marker = src.copy_to_bytes(16);
        if *marker != crate::MARKER {
            return Err(Error::Marker);
        }
        log::trace!("Valid BGP marker, length: {length}");
        let length = (src.get_u16() - 19) as usize;
        let msg_type = src.get_u8();
        let msg_type = MessageType::from_u8(msg_type).ok_or(Error::MessageType(msg_type))?;
        let mut buf = src.split_to(length).into();
        let packet = match msg_type {
            MessageType::Open => Message::Open(Open::from_bytes(&mut buf)?),
            MessageType::Update => Message::Update(Update::from_bytes(&mut buf)?),
            MessageType::Notification => Message::Notification(Notification::from_bytes(&mut buf)?),
            MessageType::Keepalive => Message::Keepalive,
        };
        if buf.has_remaining() {
            log::debug!("Remaining bytes after decoding: {buf:?}");
            Err(Error::InternalLength(
                "message",
                std::cmp::Ordering::Greater,
            ))
        } else {
            Ok(Some(packet))
        }
    }
}

#[cfg(feature = "tokio-endec")]
impl Encoder<Message> for BgpCodec {
    // tokio requires the Error type to be `From<io::Error>`, but actually ours is `!`
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        dst.put_slice(&crate::MARKER);
        let len_pos = dst.len();
        dst.put_u16(0); // Placeholder for length
        let len = match item {
            Message::Open(msg) => {
                dst.put_u8(MessageType::Open as u8);
                msg.to_bytes(dst)
            }
            Message::Update(msg) => {
                dst.put_u8(MessageType::Update as u8);
                msg.to_bytes(dst)
            }
            Message::Notification(msg) => {
                dst.put_u8(MessageType::Notification as u8);
                msg.to_bytes(dst)
            }
            Message::Keepalive => {
                dst.put_u8(MessageType::Keepalive as u8);
                0
            }
        };
        let len = len + 19;
        let len = u16::try_from(len).expect("Message length overflow");
        let len_bytes = len.to_be_bytes();
        dst[len_pos] = len_bytes[0];
        dst[len_pos + 1] = len_bytes[1];
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

/// BGP packet component with a fixed length or containing a length field
pub trait Component {
    /// Decode the component from a buffer.
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encode the component into a buffer.
    ///
    /// Returns the number of bytes written.
    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize;

    /// Find out the length of the component, preferably without encoding it.
    fn encoded_len(&self) -> usize;
}

impl Component for Ipv4Addr {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, Error> {
        let octets = src.get_u32();
        Ok(Self::from(octets))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        dst.put_u32(self.into());
        4
    }

    fn encoded_len(&self) -> usize {
        4
    }
}

impl Component for Ipv6Addr {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, Error> {
        let mut octets = [0; 16];
        src.copy_to_slice(&mut octets);
        Ok(Self::from(octets))
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        dst.put_slice(&self.octets());
        16
    }

    fn encoded_len(&self) -> usize {
        16
    }
}

impl Component for IpAddr {
    fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, Error> {
        if src.remaining() == 4 {
            Ok(Self::V4(Ipv4Addr::from_bytes(src)?))
        } else if src.remaining() == 16 {
            Ok(Self::V6(Ipv6Addr::from_bytes(src)?))
        } else {
            Err(Error::InternalLength(
                "IP address",
                std::cmp::Ordering::Equal,
            ))
        }
    }

    fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
        match self {
            Self::V4(addr) => addr.to_bytes(dst),
            Self::V6(addr) => addr.to_bytes(dst),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::V4(addr) => addr.encoded_len(),
            Self::V6(addr) => addr.encoded_len(),
        }
    }
}

macro_rules! impl_component_for_intn {
    ($typ:ty, $getter:ident, $putter:ident, $n:expr) => {
        impl Component for $typ {
            fn from_bytes(src: &mut bytes::Bytes) -> Result<Self, Error> {
                Ok(src.$getter())
            }

            fn to_bytes(self, dst: &mut bytes::BytesMut) -> usize {
                dst.$putter(self);
                $n
            }

            fn encoded_len(&self) -> usize {
                $n
            }
        }
    };
}

impl_component_for_intn!(u8, get_u8, put_u8, 1);
impl_component_for_intn!(u16, get_u16, put_u16, 2);
impl_component_for_intn!(u32, get_u32, put_u32, 4);
impl_component_for_intn!(u64, get_u64, put_u64, 8);
