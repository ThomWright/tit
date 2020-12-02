use etherparse::{IpHeader, IpTrafficClass};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Get the IP protocol type from the numberic identifier.
pub fn ip_protocol(ip_protocol_number: u8) -> Option<etherparse::IpTrafficClass> {
  match ip_protocol_number {
    0 => Some(etherparse::IpTrafficClass::IPv6HeaderHopByHop),
    1 => Some(etherparse::IpTrafficClass::Icmp),
    2 => Some(etherparse::IpTrafficClass::Igmp),
    3 => Some(etherparse::IpTrafficClass::Ggp),
    4 => Some(etherparse::IpTrafficClass::IPv4),
    5 => Some(etherparse::IpTrafficClass::Stream),
    6 => Some(etherparse::IpTrafficClass::Tcp),
    7 => Some(etherparse::IpTrafficClass::Cbt),
    8 => Some(etherparse::IpTrafficClass::Egp),
    9 => Some(etherparse::IpTrafficClass::Igp),
    10 => Some(etherparse::IpTrafficClass::BbnRccMon),
    11 => Some(etherparse::IpTrafficClass::NvpII),
    12 => Some(etherparse::IpTrafficClass::Pup),
    13 => Some(etherparse::IpTrafficClass::Argus),
    14 => Some(etherparse::IpTrafficClass::Emcon),
    15 => Some(etherparse::IpTrafficClass::Xnet),
    16 => Some(etherparse::IpTrafficClass::Chaos),
    17 => Some(etherparse::IpTrafficClass::Udp),
    18 => Some(etherparse::IpTrafficClass::Mux),
    19 => Some(etherparse::IpTrafficClass::DcnMeas),
    20 => Some(etherparse::IpTrafficClass::Hmp),
    21 => Some(etherparse::IpTrafficClass::Prm),
    22 => Some(etherparse::IpTrafficClass::XnsIdp),
    23 => Some(etherparse::IpTrafficClass::Trunk1),
    24 => Some(etherparse::IpTrafficClass::Trunk2),
    25 => Some(etherparse::IpTrafficClass::Leaf1),
    26 => Some(etherparse::IpTrafficClass::Leaf2),
    27 => Some(etherparse::IpTrafficClass::Rdp),
    28 => Some(etherparse::IpTrafficClass::Irtp),
    29 => Some(etherparse::IpTrafficClass::IsoTp4),
    30 => Some(etherparse::IpTrafficClass::NetBlt),
    31 => Some(etherparse::IpTrafficClass::MfeNsp),
    32 => Some(etherparse::IpTrafficClass::MeritInp),
    33 => Some(etherparse::IpTrafficClass::Dccp),
    34 => Some(etherparse::IpTrafficClass::ThirdPartyConnectProtocol),
    35 => Some(etherparse::IpTrafficClass::Idpr),
    36 => Some(etherparse::IpTrafficClass::Xtp),
    37 => Some(etherparse::IpTrafficClass::Ddp),
    38 => Some(etherparse::IpTrafficClass::IdprCmtp),
    39 => Some(etherparse::IpTrafficClass::TpPlusPlus),
    40 => Some(etherparse::IpTrafficClass::Il),
    41 => Some(etherparse::IpTrafficClass::Ipv6),
    42 => Some(etherparse::IpTrafficClass::Sdrp),
    43 => Some(etherparse::IpTrafficClass::IPv6RouteHeader),
    44 => Some(etherparse::IpTrafficClass::IPv6FragmentationHeader),
    45 => Some(etherparse::IpTrafficClass::Idrp),
    46 => Some(etherparse::IpTrafficClass::Rsvp),
    47 => Some(etherparse::IpTrafficClass::Gre),
    48 => Some(etherparse::IpTrafficClass::Dsr),
    49 => Some(etherparse::IpTrafficClass::Bna),
    50 => Some(etherparse::IpTrafficClass::IPv6EncapSecurityPayload),
    51 => Some(etherparse::IpTrafficClass::IPv6AuthenticationHeader),
    52 => Some(etherparse::IpTrafficClass::Inlsp),
    53 => Some(etherparse::IpTrafficClass::Swipe),
    54 => Some(etherparse::IpTrafficClass::Narp),
    55 => Some(etherparse::IpTrafficClass::Mobile),
    56 => Some(etherparse::IpTrafficClass::Tlsp),
    57 => Some(etherparse::IpTrafficClass::Skip),
    58 => Some(etherparse::IpTrafficClass::IPv6Icmp),
    59 => Some(etherparse::IpTrafficClass::IPv6NoNextHeader),
    60 => Some(etherparse::IpTrafficClass::IPv6DestinationOptions),
    61 => Some(etherparse::IpTrafficClass::AnyHostInternalProtocol),
    62 => Some(etherparse::IpTrafficClass::Cftp),
    63 => Some(etherparse::IpTrafficClass::AnyLocalNetwork),
    64 => Some(etherparse::IpTrafficClass::SatExpak),
    65 => Some(etherparse::IpTrafficClass::Krytolan),
    66 => Some(etherparse::IpTrafficClass::Rvd),
    67 => Some(etherparse::IpTrafficClass::Ippc),
    68 => Some(etherparse::IpTrafficClass::AnyDistributedFileSystem),
    69 => Some(etherparse::IpTrafficClass::SatMon),
    70 => Some(etherparse::IpTrafficClass::Visa),
    71 => Some(etherparse::IpTrafficClass::Ipcv),
    72 => Some(etherparse::IpTrafficClass::Cpnx),
    73 => Some(etherparse::IpTrafficClass::Cphb),
    74 => Some(etherparse::IpTrafficClass::Wsn),
    75 => Some(etherparse::IpTrafficClass::Pvp),
    76 => Some(etherparse::IpTrafficClass::BrSatMon),
    77 => Some(etherparse::IpTrafficClass::SunNd),
    78 => Some(etherparse::IpTrafficClass::WbMon),
    79 => Some(etherparse::IpTrafficClass::WbExpak),
    80 => Some(etherparse::IpTrafficClass::IsoIp),
    81 => Some(etherparse::IpTrafficClass::Vmtp),
    82 => Some(etherparse::IpTrafficClass::SecureVmtp),
    83 => Some(etherparse::IpTrafficClass::Vines),
    84 => Some(etherparse::IpTrafficClass::TtpOrIptm),
    85 => Some(etherparse::IpTrafficClass::NsfnetIgp),
    86 => Some(etherparse::IpTrafficClass::Dgp),
    87 => Some(etherparse::IpTrafficClass::Tcf),
    88 => Some(etherparse::IpTrafficClass::Eigrp),
    89 => Some(etherparse::IpTrafficClass::Ospfigp),
    90 => Some(etherparse::IpTrafficClass::SpriteRpc),
    91 => Some(etherparse::IpTrafficClass::Larp),
    92 => Some(etherparse::IpTrafficClass::Mtp),
    93 => Some(etherparse::IpTrafficClass::Ax25),
    94 => Some(etherparse::IpTrafficClass::Ipip),
    95 => Some(etherparse::IpTrafficClass::Micp),
    96 => Some(etherparse::IpTrafficClass::SccSp),
    97 => Some(etherparse::IpTrafficClass::EtherIp),
    98 => Some(etherparse::IpTrafficClass::Encap),
    100 => Some(etherparse::IpTrafficClass::Gmtp),
    101 => Some(etherparse::IpTrafficClass::Ifmp),
    102 => Some(etherparse::IpTrafficClass::Pnni),
    103 => Some(etherparse::IpTrafficClass::Pim),
    104 => Some(etherparse::IpTrafficClass::Aris),
    105 => Some(etherparse::IpTrafficClass::Scps),
    106 => Some(etherparse::IpTrafficClass::Qnx),
    107 => Some(etherparse::IpTrafficClass::ActiveNetworks),
    108 => Some(etherparse::IpTrafficClass::IpComp),
    109 => Some(etherparse::IpTrafficClass::SitraNetworksProtocol),
    110 => Some(etherparse::IpTrafficClass::CompaqPeer),
    111 => Some(etherparse::IpTrafficClass::IpxInIp),
    112 => Some(etherparse::IpTrafficClass::Vrrp),
    113 => Some(etherparse::IpTrafficClass::Pgm),
    114 => Some(etherparse::IpTrafficClass::AnyZeroHopProtocol),
    115 => Some(etherparse::IpTrafficClass::Layer2TunnelingProtocol),
    116 => Some(etherparse::IpTrafficClass::Ddx),
    117 => Some(etherparse::IpTrafficClass::Iatp),
    118 => Some(etherparse::IpTrafficClass::Stp),
    119 => Some(etherparse::IpTrafficClass::Srp),
    120 => Some(etherparse::IpTrafficClass::Uti),
    121 => Some(etherparse::IpTrafficClass::SimpleMessageProtocol),
    122 => Some(etherparse::IpTrafficClass::Sm),
    123 => Some(etherparse::IpTrafficClass::Ptp),
    124 => Some(etherparse::IpTrafficClass::IsisOverIpv4),
    125 => Some(etherparse::IpTrafficClass::Fire),
    126 => Some(etherparse::IpTrafficClass::Crtp),
    127 => Some(etherparse::IpTrafficClass::Crudp),
    128 => Some(etherparse::IpTrafficClass::Sscopmce),
    129 => Some(etherparse::IpTrafficClass::Iplt),
    130 => Some(etherparse::IpTrafficClass::Sps),
    131 => Some(etherparse::IpTrafficClass::Pipe),
    132 => Some(etherparse::IpTrafficClass::Sctp),
    133 => Some(etherparse::IpTrafficClass::Fc),
    134 => Some(etherparse::IpTrafficClass::RsvpE2eIgnore),
    135 => Some(etherparse::IpTrafficClass::MobilityHeader),
    136 => Some(etherparse::IpTrafficClass::UdpLite),
    137 => Some(etherparse::IpTrafficClass::MplsInIp),
    138 => Some(etherparse::IpTrafficClass::Manet),
    139 => Some(etherparse::IpTrafficClass::Hip),
    140 => Some(etherparse::IpTrafficClass::Shim6),
    141 => Some(etherparse::IpTrafficClass::Wesp),
    142 => Some(etherparse::IpTrafficClass::Rohc),
    253 => Some(etherparse::IpTrafficClass::ExperimentalAndTesting0),
    254 => Some(etherparse::IpTrafficClass::ExperimentalAndTesting1),
    _ => None,
  }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum IpPair {
  V4 { src: Ipv4Addr, dst: Ipv4Addr },
  V6 { src: Ipv6Addr, dst: Ipv6Addr },
}

impl Display for IpPair {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      IpPair::V4 { src, .. } => write!(f, "{}", src)?,
      IpPair::V6 { src, .. } => write!(f, "{}", src)?,
    };
    write!(f, " -> ")?;
    match self {
      IpPair::V4 { dst, .. } => write!(f, "{}", dst)?,
      IpPair::V6 { dst, .. } => write!(f, "{}", dst)?,
    };
    Ok(())
  }
}

impl From<&IpHeader> for IpPair {
  fn from(ip: &IpHeader) -> Self {
    match ip {
      IpHeader::Version4(header) => IpPair::V4 {
        src: Ipv4Addr::from(header.source),
        dst: Ipv4Addr::from(header.destination),
      },
      IpHeader::Version6(header) => IpPair::V6 {
        src: Ipv6Addr::from(header.source),
        dst: Ipv6Addr::from(header.destination),
      },
    }
  }
}

pub fn get_next_protocol(ip: &IpHeader) -> IpTrafficClass {
  ip_protocol(match ip {
    IpHeader::Version4(header) => header.protocol,
    IpHeader::Version6(header) => header.next_header,
  })
  .expect("Unknown IP protocol number")
}
