# paBGP

A pretty average BGP implementation in Rust.

## Supported Features
It implements most of the modern BGP data structures and messages, as well as
utilities to easily create them with builder patterns, encode them to bytes,
and decode them from bytes.

Next-to-full support for:
- Base BGP-4 ([RFC4271](https://tools.ietf.org/html/rfc4271))
- BGP Capabilities ([RFC5492](https://tools.ietf.org/html/rfc5492))
- Multiprotocol Extensions for BGP-4 (cap 1) ([RFC4760](https://tools.ietf.org/html/rfc4760))
- IPv4 over IPv6 next-hop (cap 5) ([RFC8950](https://tools.ietf.org/html/rfc8950))
- Four-octet AS numbers (cap 65) ([RFC6793](https://tools.ietf.org/html/rfc6793))

Basic support for:
- Route Refresh (cap 2) ([RFC2918](https://tools.ietf.org/html/rfc2918))
- Extended Messages for BGP (cap 6) ([RFC8654](https://tools.ietf.org/html/rfc8654))

Open-ended enum variants exist to support manually parsing and encoding
unsupported or custom BGP capabilities and path attributes.

## About
This project is a spin-off from `delegation-feed` (also in this Cargo workspace).
However, it contains enough features to be useful on its own for creating BGP
applications.
