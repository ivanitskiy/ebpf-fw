#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use myapp_common::BackendPorts;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map(name = "BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> =
    HashMap::<u16, BackendPorts>::with_max_entries(10, 0);

#[xdp]
pub fn myapp(ctx: XdpContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
#[allow(unused)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

fn try_myapp(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => {
            // info!(&ctx, "received IPv4 packet");
        }
        EtherType::Ipv6 => {
            info!(&ctx, "received IPv6 packet. Drop it");
            return Ok(xdp_action::XDP_DROP);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let ipv4hdr = unsafe { *ipv4hdr };
    let source_addr = u32::from_be(ipv4hdr.src_addr);

    let dst_addr = u32::from_be(ipv4hdr.dst_addr);

    let (source_port, dst_port) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            let tcphdr = unsafe { *tcphdr };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            let udphdr = unsafe { *udphdr };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Ok(0),
    };

    if let Some(v) = unsafe { BACKEND_PORTS.get(&dst_port) } {
        if v.ips.iter().any(|&x| x == source_addr) {
            info!(&ctx, "source addr should be blocked");
            return Ok(xdp_action::XDP_DROP);
        }
    }
    let proto = WrappedIpProto(ipv4hdr.proto);
    info!(
        &ctx,
        "ingress: {} {:i}:{} {:i}:{} not matching FW rule",
        proto.as_str(),
        source_addr,
        source_port,
        dst_addr,
        dst_port
    );
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
pub struct WrappedIpProto(pub IpProto);

impl WrappedIpProto {
    fn as_str(&self) -> &str {
        match self.0 {
            IpProto::HopOpt => "HopOpt",
            IpProto::Icmp => "Icmp",
            IpProto::Igmp => "Igmp",
            IpProto::Ggp => "Ggp",
            IpProto::Ipv4 => "Ipv4",
            IpProto::Stream => "Stream",
            IpProto::Tcp => "Tcp",
            IpProto::Cbt => "Cbt",
            IpProto::Egp => "Egp",
            IpProto::Igp => "Igp",
            IpProto::BbnRccMon => "BbnRccMon",
            IpProto::NvpII => "NvpII",
            IpProto::Pup => "Pup",
            IpProto::Argus => "Argus",
            IpProto::Emcon => "Emcon",
            IpProto::Xnet => "Xnet",
            IpProto::Chaos => "Chaos",
            IpProto::Udp => "Udp",
            IpProto::Mux => "Mux",
            IpProto::DcnMeas => "DcnMeas",
            IpProto::Hmp => "Hmp",
            IpProto::Prm => "Prm",
            IpProto::Idp => "Idp",
            IpProto::Trunk1 => "Trunk1",
            IpProto::Trunk2 => "Trunk2",
            IpProto::Leaf1 => "Leaf1",
            IpProto::Leaf2 => "Leaf2",
            IpProto::Rdp => "Rdp",
            IpProto::Irtp => "Irtp",
            IpProto::Tp4 => "Tp4",
            IpProto::Netblt => "Netblt",
            IpProto::MfeNsp => "MfeNsp",
            IpProto::MeritInp => "MeritInp",
            IpProto::Dccp => "Dccp",
            IpProto::ThirdPartyConnect => "ThirdPartyConnect",
            IpProto::Idpr => "Idpr",
            IpProto::Xtp => "Xtp",
            IpProto::Ddp => "Ddp",
            IpProto::IdprCmtp => "IdprCmtp",
            IpProto::TpPlusPlus => "TpPlusPlus",
            IpProto::Il => "Il",
            IpProto::Ipv6 => "Ipv6",
            IpProto::Sdrp => "Sdrp",
            IpProto::Ipv6Route => "Ipv6Route",
            IpProto::Ipv6Frag => "Ipv6Frag",
            IpProto::Idrp => "Idrp",
            IpProto::Rsvp => "Rsvp",
            IpProto::Gre => "Gre",
            IpProto::Dsr => "Dsr",
            IpProto::Bna => "Bna",
            IpProto::Esp => "Esp",
            IpProto::Ah => "Ah",
            IpProto::Inlsp => "Inlsp",
            IpProto::Swipe => "Swipe",
            IpProto::Narp => "Narp",
            IpProto::Mobile => "Mobile",
            IpProto::Tlsp => "Tlsp",
            IpProto::Skip => "Skip",
            IpProto::Ipv6Icmp => "Ipv6Icmp",
            IpProto::Ipv6NoNxt => "Ipv6NoNxt",
            IpProto::Ipv6Opts => "Ipv6Opts",
            IpProto::AnyHostInternal => "AnyHostInternal",
            IpProto::Cftp => "Cftp",
            IpProto::AnyLocalNetwork => "AnyLocalNetwork",
            IpProto::SatExpak => "SatExpak",
            IpProto::Kryptolan => "Kryptolan",
            IpProto::Rvd => "Rvd",
            IpProto::Ippc => "Ippc",
            IpProto::AnyDistributedFileSystem => "AnyDistributedFileSystem",
            IpProto::SatMon => "SatMon",
            IpProto::Visa => "Visa",
            IpProto::Ipcv => "Ipcv",
            IpProto::Cpnx => "Cpnx",
            IpProto::Cphb => "Cphb",
            IpProto::Wsn => "Wsn",
            IpProto::Pvp => "Pvp",
            IpProto::BrSatMon => "BrSatMon",
            IpProto::SunNd => "SunNd",
            IpProto::WbMon => "WbMon",
            IpProto::WbExpak => "WbExpak",
            IpProto::IsoIp => "IsoIp",
            IpProto::Vmtp => "Vmtp",
            IpProto::SecureVmtp => "SecureVmtp",
            IpProto::Vines => "Vines",
            IpProto::Ttp => "Ttp",
            IpProto::NsfnetIgp => "NsfnetIgp",
            IpProto::Dgp => "Dgp",
            IpProto::Tcf => "Tcf",
            IpProto::Eigrp => "Eigrp",
            IpProto::Ospfigp => "Ospfigp",
            IpProto::SpriteRpc => "SpriteRpc",
            IpProto::Larp => "Larp",
            IpProto::Mtp => "Mtp",
            IpProto::Ax25 => "Ax25",
            IpProto::Ipip => "Ipip",
            IpProto::Micp => "Micp",
            IpProto::SccSp => "SccSp",
            IpProto::Etherip => "Etherip",
            IpProto::Encap => "Encap",
            IpProto::AnyPrivateEncryptionScheme => "AnyPrivateEncryptionScheme",
            IpProto::Gmtp => "Gmtp",
            IpProto::Ifmp => "Ifmp",
            IpProto::Pnni => "Pnni",
            IpProto::Pim => "Pim",
            IpProto::Aris => "Aris",
            IpProto::Scps => "Scps",
            IpProto::Qnx => "Qnx",
            IpProto::ActiveNetworks => "ActiveNetworks",
            IpProto::IpComp => "IpComp",
            IpProto::Snp => "Snp",
            IpProto::CompaqPeer => "CompaqPeer",
            IpProto::IpxInIp => "IpxInIp",
            IpProto::Vrrp => "Vrrp",
            IpProto::Pgm => "Pgm",
            IpProto::AnyZeroHopProtocol => "AnyZeroHopProtocol",
            IpProto::L2tp => "L2tp",
            IpProto::Ddx => "Ddx",
            IpProto::Iatp => "Iatp",
            IpProto::Stp => "Stp",
            IpProto::Srp => "Srp",
            IpProto::Uti => "Uti",
            IpProto::Smp => "Smp",
            IpProto::Sm => "Sm",
            IpProto::Ptp => "Ptp",
            IpProto::IsisOverIpv4 => "IsisOverIpv4",
            IpProto::Fire => "Fire",
            IpProto::Crtp => "Crtp",
            IpProto::Crudp => "Crudp",
            IpProto::Sscopmce => "Sscopmce",
            IpProto::Iplt => "Iplt",
            IpProto::Sps => "Sps",
            IpProto::Pipe => "Pipe",
            IpProto::Sctp => "Sctp",
            IpProto::Fc => "Fc",
            IpProto::RsvpE2eIgnore => "RsvpE2eIgnore",
            IpProto::MobilityHeader => "MobilityHeader",
            IpProto::UdpLite => "UdpLite",
            IpProto::Mpls => "Mpls",
            IpProto::Manet => "Manet",
            IpProto::Hip => "Hip",
            IpProto::Shim6 => "Shim6",
            IpProto::Wesp => "Wesp",
            IpProto::Rohc => "Rohc",
            IpProto::EthernetInIpv4 => "EthernetInIpv4",
            IpProto::Aggfrag => "Aggfrag",
            IpProto::Test1 => "Test1",
            IpProto::Test2 => "Test2",
            IpProto::Reserved => "Reserved",
        }
    }
}
