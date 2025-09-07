#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
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
        Err(_) => xdp_action::XDP_PASS,
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
            swap_macaddrs(ethhdr);
            swap_ipv4addrs(ipv4hdr);
            swap_ports(tcphdr);
            rewrite_payload(&ctx, WOOLONG_WORD_SLICE)?;
            rewrite_seq_ack(tcphdr, WOOLONG_WORD_SLICE.len())?;
            rewrite_flags(tcphdr)?;
            // reculc_ipv4_csum(ipv4hdr);
            // reculc_tcp_csum(&ctx, ipv4hdr, tcphdr)?;
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

fn swap_macaddrs(ethhdr: *const EthHdr) {
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    unsafe { (*(ethhdr as *mut EthHdr)).src_addr = dst_mac; }
    unsafe { (*(ethhdr as *mut EthHdr)).dst_addr = src_mac; }
}

fn swap_ipv4addrs(ipv4hdr: *const Ipv4Hdr) {
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    unsafe { (*(ipv4hdr as *mut Ipv4Hdr)).src_addr = dst_ip; }
    unsafe { (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = src_ip; }
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
    let end = ctx.data_end();

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 12;
    
    if new.len() != SHENRON_WORD_SLICE.len() { return Err(()) }

    if start + payload_offset + SHENRON_WORD_SLICE.len() > end {
        return Err(());
    }

    let mut i = 0usize;
    while i < SHENRON_WORD_SLICE.len() {
        let np = unsafe { *new.get_unchecked(i) };
        unsafe { core::ptr::write_unaligned((start + payload_offset + i) as *mut u8, np); }
        i += 1;
    };
    Ok(())
}

fn rewrite_seq_ack(tcphdr: *const TcpHdr, payload_len: usize) -> Result<(), ()> {
    let old_seq = u32::from_be_bytes(unsafe { (*tcphdr).seq });
    let old_ack = u32::from_be_bytes(unsafe { (*tcphdr).ack_seq });

    let syn = unsafe { (*tcphdr).syn() != 0 };
    let fin = unsafe { (*tcphdr).fin() != 0 };
    let inc = payload_len + if syn { 1 } else { 0 } + if fin { 1 } else { 0 };

    let new_seq = old_ack;
    let new_ack = old_seq.wrapping_add(inc as u32);

    unsafe { (*(tcphdr as *mut TcpHdr)).seq = new_seq.to_be_bytes(); }
    unsafe { (*(tcphdr as *mut TcpHdr)).ack_seq = new_ack.to_be_bytes(); }
    Ok(())
}

fn rewrite_flags(tcphdr: *const TcpHdr) -> Result<(), ()> {
    unsafe {
        (*(tcphdr as *mut TcpHdr)).set_syn(0);
        (*(tcphdr as *mut TcpHdr)).set_fin(0);
        (*(tcphdr as *mut TcpHdr)).set_ack(1);
        (*(tcphdr as *mut TcpHdr)).set_rst(0);
    }
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
