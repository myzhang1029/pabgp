# delegation-feed

[![wakatime](https://wakatime.com/badge/user/c96e4e50-983b-4d67-8990-09527f44865b/project/528870f5-7740-4731-909f-ab9c1b0cad6f.svg)](https://wakatime.com/badge/user/c96e4e50-983b-4d67-8990-09527f44865b/project/528870f5-7740-4731-909f-ab9c1b0cad6f)

Fetch and parse RIR delegation files and feed the data through BGP.


This project is inspired by [`cn-routefeed`](https://github.com/Nat-Lab/cn-routefeed)
and includes support for all countries and RIRs, as well as more modern BGP features
like 4-octet ASNs and IPv6 thanks to [paBGP](https://github.com/myzhang1029/pabgp).

It is also free from `cn-routefeed`'s memory leaks and segfaults thanks to Rust.
