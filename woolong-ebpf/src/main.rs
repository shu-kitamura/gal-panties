#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

mod rewrite_packet;

const SHENRON_WORD_SLICE: &[u8] = "願いを言え。どんな願いもひとつだけ叶えてやろう".as_bytes();
const WOOLONG_WORD_SLICE: &[u8] = "ギャルのパンティおくれーーーーーーっ！！！！！".as_bytes();

#[xdp]
pub fn woolong(ctx: XdpContext) -> u32 {
    match try_woolong(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_woolong(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ipv4hdr: *const Ipv4Hdr = get_ipv4hdr(&ctx, ethhdr).ok_or(())?;
    let tcphdr: *const TcpHdr = get_tcphdr(&ctx, ipv4hdr).ok_or(())?;
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;

    let (source_port, _dest_port) = get_ports(tcphdr);

    if source_port == 7777 && payload_eq_slice(&ctx, payload_offset, SHENRON_WORD_SLICE) {
        rewrite_packet::swap_macaddrs(ethhdr);
        rewrite_packet::swap_ipv4addrs(ipv4hdr);
        rewrite_packet::swap_ports(tcphdr);
        rewrite_packet::rewrite_payload(&ctx, WOOLONG_WORD_SLICE)?;
        rewrite_packet::rewrite_seq_ack(tcphdr,WOOLONG_WORD_SLICE.len())?;
        rewrite_packet::rewrite_flags(tcphdr)?;
        rewrite_packet::recalc_tcp_csum(&ctx, ipv4hdr, tcphdr)?;
        return Ok(xdp_action::XDP_TX);
    }
    Ok(xdp_action::XDP_PASS)
}

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn load_u64(p: *const u8) -> u64 {
    unsafe { core::ptr::read_unaligned(p as *const u64) }
}

#[inline(always)]
fn add_carry(sum:u32, w: u16) -> u32 {
    let s = sum + w as u32;
    (s & 0xffff) + (s >> 16)
}

fn fold_csum(mut csum: u32) -> u16 {
    // 1's complement fold
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !(csum as u16)
}


fn get_ipv4hdr(ctx: &XdpContext, ethhdr: *const EthHdr) -> Option<*const Ipv4Hdr> {
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => ptr_at(ctx, EthHdr::LEN).ok(),
        _ => None, // IPv4 以外は考慮しない
    }
}

fn get_tcphdr(ctx: &XdpContext, ipv4hdr: *const Ipv4Hdr) -> Option<*const TcpHdr> {
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let ihl = ((unsafe { (*ipv4hdr).vihl } & 0x0f) as usize) * 4;
            ptr_at(ctx, EthHdr::LEN + ihl).ok()
        }
        _ => None // 今回は TCP 以外は考慮しない
    }
}

fn get_ports(tcphdr: *const TcpHdr) -> (u16, u16) {
    let src_port: u16 = u16::from_be_bytes(unsafe { (*tcphdr).source });
    let dst_port: u16 = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    (src_port, dst_port)
}

fn payload_eq_slice(ctx: &XdpContext, off: usize, pat: &[u8]) -> bool {
    if pat.len() < 8 { return false; }

    let start = ctx.data();
    let end = ctx.data_end();

    let p = start + off;
    if p + 8 > end {
        return false;
    }
    
    let payload_head = load_u64(p as *const u8);
    let pattern_head = load_u64(pat.as_ptr());

    payload_head == pattern_head
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
