//! BGP packet parsing tests

use super::capability::*;
use super::cidr::Cidr4;
use super::endec::*;
use super::path::*;
use super::route::*;
use super::*;
use bytes::{Bytes, BytesMut};
use std::net::Ipv6Addr;
use tokio_util::codec::{Decoder, Encoder};

#[test]
fn test_sanity_hex_to_bytes() {
    assert_eq!(hex_to_bytes("00"), Bytes::from_static(&[0x00]));
    assert_eq!(hex_to_bytes("01"), Bytes::from_static(&[0x01]));
    assert_eq!(hex_to_bytes("ff"), Bytes::from_static(&[0xff]));
    assert_eq!(hex_to_bytes("00ff"), Bytes::from_static(&[0x00, 0xff]));
    assert_eq!(hex_to_bytes("ff00"), Bytes::from_static(&[0xff, 0x00]));
    assert_eq!(
        hex_to_bytes("ff 00\tff"),
        Bytes::from_static(&[0xff, 0x00, 0xff])
    );
}

#[test]
fn test_keepalive_message() {
    let data = hex_to_bytes("ffffffffffffffffffffffffffffffff001304");
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    assert_eq!(msg, Message::Keepalive);
    let mut bmut = BytesMut::new();
    codec.encode(Message::Keepalive, &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}

#[test]
fn test_open_message_wsh_1() {
    // Dumped from a real BGP session (Wireshark and BIRD)
    let data = hex_to_bytes("ffffffffffffffffffffffffffffffff 001d 01 04 fd7d 0078 ac1706a5 00");
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    let Message::Open(msg) = msg else {
        panic!("unexpected message type");
    };
    assert_eq!(msg.version, 4);
    assert_eq!(msg.asn, 64893);
    assert_eq!(msg.hold_time, 120);
    assert_eq!(msg.bgp_id, Ipv4Addr::new(172, 23, 6, 165));
    assert_eq!(msg.opt_params.len(), 0);
    let mut bmut = BytesMut::new();
    codec.encode(Message::Open(msg), &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}

#[test]
fn test_open_message_wsh_2() {
    // Dumped from a real BGP session (Wireshark and BIRD)
    let data = hex_to_bytes("ffffffffffffffffffffffffffffffff004501045ba000f0ac1706a2280226010400010001010400020001020005060001000100020600400200784104fcde349d46004700");
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    let Message::Open(msg) = msg else {
        panic!("unexpected message type");
    };
    assert_eq!(msg.version, 4);
    assert_eq!(msg.asn, AS_TRANS);
    assert_eq!(msg.hold_time, 240);
    assert_eq!(msg.bgp_id, Ipv4Addr::new(172, 23, 6, 162));
    let OptionalParameterValue::Capabilities(cap) = &msg.opt_params.first().unwrap();
    assert_eq!(cap.len(), 9);
    assert_eq!(
        *cap.first().unwrap(),
        capability::Value::MultiProtocol(MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
    );
    assert_eq!(
        *cap.get(1).unwrap(),
        capability::Value::MultiProtocol(MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
    );
    assert_eq!(*cap.get(2).unwrap(), capability::Value::RouteRefresh);
    assert_eq!(
        *cap.get(3).unwrap(),
        capability::Value::ExtendedNextHop(ExtendedNextHop(vec![ExtendedNextHopValue {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop_afi: Afi::Ipv6,
        }]))
    );
    assert_eq!(*cap.get(4).unwrap(), capability::Value::ExtendedMessage);
    assert_eq!(
        *cap.get(5).unwrap(),
        capability::Value::Unsupported(0x40, Bytes::from_static(&[0x00, 0x78]))
    );
    assert_eq!(
        *cap.get(6).unwrap(),
        capability::Value::FourOctetAsNumber(FourOctetAsNumber { asn: 4_242_420_893 })
    );
    assert_eq!(
        *cap.get(7).unwrap(),
        capability::Value::Unsupported(0x46, Bytes::from_static(&[]))
    );
    assert_eq!(
        *cap.get(8).unwrap(),
        capability::Value::Unsupported(0x47, Bytes::from_static(&[]))
    );
    let mut bmut = BytesMut::new();
    codec.encode(Message::Open(msg), &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}

#[test]
fn test_update_message_wsh_1() {
    // Dumped from a real BGP session (Wireshark and BIRD)
    let data = hex_to_bytes(
        "
    ffffffffffffffffffffffffffffffff 0042 02 0000 001b
    40 01 01 00
    40 02 04 0201 fd7d
    40 03 04 ac1706a5
    c0 11 06 0201 0000fd7d
    162dff30
    162dfe30
    162d7b80
    18cb0486",
    );
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    let Message::Update(msg) = msg else {
        panic!("unexpected message type");
    };
    assert_eq!(msg.withdrawn_routes.len(), 0);
    assert_eq!(msg.path_attributes.len(), 4);
    assert_eq!(
        *msg.path_attributes.first().unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::Origin(Origin::Igp),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(1).unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::AsPath(AsPath(vec![AsSegment {
                type_: AsSegmentType::AsSequence,
                asns: vec![0xfd7d],
                as4: false,
            }])),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(2).unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::NextHop(Ipv4Addr::new(172, 23, 6, 165)),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(3).unwrap(),
        path::Value {
            flags: path::Flags(0xc0),
            data: path::Data::As4Path(AsPath(vec![AsSegment {
                type_: AsSegmentType::AsSequence,
                asns: vec![0xfd7d],
                as4: true,
            }])),
        }
    );
    assert_eq!(msg.nlri.len(), 4);
    let mut bmut = BytesMut::new();
    codec.encode(Message::Update(msg), &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}

#[test]
fn test_update_message_wsh_2() {
    // Dumped from a real BGP session (Wireshark and BIRD)
    let data = hex_to_bytes(
        "
    ffffffffffffffffffffffffffffffff 008a 02 0000 0073

    90 0e 0029 0001 01
        20 fdc0:d227:0306:ee01:0000:0000:0000:0161 fe80:0000:0000:0000:84cf:65ff:fead:2f30
        00
        18 ac17e3

    40 01 01 00
    40 02 0e 0203 fcde39d1 fcde3880 fcde3122
    40 05 04 00000064
    c0 08 0c
        fbff 0004
        fbff 0018
        fbff 0022
    e0 20 18
        fcde3880 00000064 00000035
        fcde3880 00000065 0000040c",
    );
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    let Message::Update(msg) = msg else {
        panic!("unexpected message type");
    };
    assert_eq!(msg.withdrawn_routes.len(), 0);
    assert_eq!(msg.path_attributes.len(), 6);
    assert_eq!(
        *msg.path_attributes.first().unwrap(),
        path::Value {
            flags: path::Flags(0x90),
            data: path::Data::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: MpNextHop::V6AndLL(
                    Ipv6Addr::new(0xfdc0, 0xd227, 0x0306, 0xee01, 0, 0, 0, 0x0161),
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0x84cf, 0x65ff, 0xfead, 0x2f30)
                ),
                nlri: Routes(vec![Cidr4 {
                    addr: Ipv4Addr::new(172, 23, 227, 0),
                    prefix_len: 24,
                }
                .into()]),
            }),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(1).unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::Origin(Origin::Igp),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(2).unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::AsPath(AsPath(vec![AsSegment {
                type_: AsSegmentType::AsSequence,
                asns: vec![0xfcde_39d1, 0xfcde_3880, 0xfcde_3122],
                as4: true,
            }])),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(3).unwrap(),
        path::Value {
            flags: path::Flags(0x40),
            data: path::Data::LocalPref(100),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(4).unwrap(),
        path::Value {
            flags: path::Flags(0xc0),
            data: path::Data::Unsupported(
                0x08,
                Bytes::from_static(&[
                    0xfb, 0xff, 0x00, 0x04, 0xfb, 0xff, 0x00, 0x18, 0xfb, 0xff, 0x00, 0x22
                ])
            ),
        }
    );
    assert_eq!(
        *msg.path_attributes.get(5).unwrap(),
        path::Value {
            flags: path::Flags(0xe0),
            data: path::Data::Unsupported(
                0x20,
                Bytes::from_static(&[
                    0xfc, 0xde, 0x38, 0x80, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x35, 0xfc,
                    0xde, 0x38, 0x80, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x04, 0x0c
                ])
            ),
        }
    );
    let mut bmut = BytesMut::new();
    codec.encode(Message::Update(msg), &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}

#[test]
fn test_notification_message_wsh_1() {
    // Dumped from a real BGP session (Wireshark and BIRD)
    let data = hex_to_bytes("ffffffffffffffffffffffffffffffff 0015 03 06 02");
    let mut bmut = data.clone().into();
    let mut codec = BgpCodec;
    let msg = codec.decode(&mut bmut).unwrap().unwrap();
    let Message::Notification(msg) = msg else {
        panic!("unexpected message type");
    };
    assert_eq!(msg.error_code, NotificationErrorCode::Cease);
    assert_eq!(
        msg.error_subcode,
        CeaseSubcode::AdministrativeShutdown as u8
    );
    assert_eq!(msg.data, Bytes::from_static(&[]));
    let mut bmut = BytesMut::new();
    codec.encode(Message::Notification(msg), &mut bmut).unwrap();
    assert_eq!(bmut.freeze(), data);
}
