#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, helpers::r#gen::bpf_csum_diff, macros::xdp, programs::XdpContext};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const SHENRON_WORD_SLICE: &[u8] = "願いを言え。どんな願いもひとつだけ叶えてやろう".as_bytes();
const WOOLONG_WORD_SLICE: &[u8] = "ギャルのパンティおくれーーーーーーっ！！！！！".as_bytes();

#[xdp]
pub fn woolong(ctx: XdpContext) -> u32 {
    match try_woolong(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
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
fn load_u8(p: *const u8) -> u8 {
    unsafe { core::ptr::read_unaligned(p) }
}

fn try_woolong(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ipv4hdr: *const Ipv4Hdr = get_ipv4hdr(&ctx, ethhdr).ok_or(())?;
    let tcphdr: *const TcpHdr = get_tcphdr(&ctx, ipv4hdr).ok_or(())?;
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 12;

    let (source_port, _dest_port) = get_ports(tcphdr);

    if source_port == 7777  {
        if payload_eq_slice(&ctx, payload_offset, SHENRON_WORD_SLICE) {
            rewrite_payload(&ctx, WOOLONG_WORD_SLICE)?;
            swap_ports(tcphdr);
            rewrite_tcp_checksum(&ctx, tcphdr, payload_offset, SHENRON_WORD_SLICE.len(), WOOLONG_WORD_SLICE)?;
            return Ok(xdp_action::XDP_TX);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

fn get_ipv4hdr(ctx: &XdpContext, ethhdr: *const EthHdr) -> Option<*const Ipv4Hdr> {
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => ptr_at(ctx, EthHdr::LEN).ok(),
        _ => None, // IPv4 以外は考慮しない
    }
}

fn get_tcphdr(ctx: &XdpContext, ipv4hdr: *const Ipv4Hdr) -> Option<*const TcpHdr> {
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok(),
        _ => None // 今回は TCP 以外は考慮しない
    }
}

fn get_ports(tcphdr: *const TcpHdr) -> (u16, u16) {
    let src_port: u16 = u16::from_be_bytes(unsafe { (*tcphdr).source });
    let dst_port: u16 = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    (src_port, dst_port)
}

fn swap_ports(tcphdr: *const TcpHdr) {
    let src_port = unsafe { (*tcphdr).source };
    let dst_port = unsafe { (*tcphdr).dest };

    unsafe { (*(tcphdr as *mut TcpHdr)).source = dst_port; }
    unsafe { (*(tcphdr as *mut TcpHdr)).dest = src_port; }
}

fn payload_eq_slice(ctx: &XdpContext, off: usize, pat: &[u8]) -> bool {
    let start = ctx.data();
    let end = ctx.data_end();
    let n = pat.len();

    // ★ これが肝：使う前に n バイト分まとめて境界チェック
    if start + off + n > end { return false; }

    let mut i = 0usize;
    // 自前ループ（memcmp を呼ばせない＆境界は上で証明済み）
    while i < n {
        let b_pkt = load_u8((start + off + i) as *const u8);
        // pat[i] は bounds チェックで panic 経路が入るので get_unchecked を使う
        let b_pat = unsafe { *pat.get_unchecked(i) };
        if b_pkt != b_pat { return false; }
        i += 1;
    }
    true
}

fn rewrite_payload(ctx: &XdpContext, new: &[u8]) -> Result<(), ()> {
    let start = ctx.data();
    // let end = ctx.data_end();

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 12;
    
    if new.len() != SHENRON_WORD_SLICE.len() { return Err(()) }

    let mut i = 0usize;
    while i < SHENRON_WORD_SLICE.len() {
        let np = unsafe { *new.get_unchecked(i) };
        unsafe { core::ptr::write_unaligned((start + payload_offset + i) as *mut u8, np); }
        i += 1;
    };
    Ok(())
}

fn rewrite_tcp_checksum(
    ctx: &XdpContext,
    tcphdr: *const TcpHdr,
    payload_offset: usize,
    old_len: usize,
    new: &[u8]
) -> Result<(), ()> {
    if new.len() != old_len { return Err(()); }

    let start = ctx.data();
    let end = ctx.data_end();
    if start + payload_offset + old_len > end { return Err(()); }

    let old_checksum = u16::from_be_bytes(unsafe { (*tcphdr).check });

    let seed = !old_checksum as u32;
    let from = (start + payload_offset) as *mut u32;
    let to = new.as_ptr() as *mut u32;

    let csum = unsafe { bpf_csum_diff(from, old_len as u32, to, new.len() as u32, seed) };

    if csum < 0 {
        return Err(());
    }

    let new_checksum = (!(csum as u32) as u16).to_be_bytes();
    unsafe { (*(tcphdr as *mut TcpHdr)).check = new_checksum; }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
