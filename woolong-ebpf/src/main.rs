#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, helpers::r#gen::bpf_csum_diff, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
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
            let (src, dst) = get_ports(tcphdr);
            info!(&ctx, "src: {}, dst: {}", src, dst);
            rewrite_payload(&ctx, WOOLONG_WORD_SLICE)?;
            rewrite_seq_ack(tcphdr, WOOLONG_WORD_SLICE.len())?;
            rewrite_flags(tcphdr)?;
            recalc_ipv4_csum(ipv4hdr);
            recalc_tcp_csum(&ctx, ipv4hdr, tcphdr)?;
            return Ok(xdp_action::XDP_TX);
        }
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

fn get_pseudo_header(ipv4hdr: *const Ipv4Hdr) -> u32 {
    let src_addr: [u8; 4] = unsafe { (*ipv4hdr).src_addr };
    let dst_addr: [u8; 4] = unsafe { (*ipv4hdr).dst_addr };

    let src_hi = u16::from_be_bytes([src_addr[0], src_addr[1]]);
    let src_lo = u16::from_be_bytes([src_addr[2], src_addr[3]]);
    let dst_hi = u16::from_be_bytes([dst_addr[0], dst_addr[1]]);
    let dst_lo = u16::from_be_bytes([dst_addr[2], dst_addr[3]]);
    let proto: u16 = 0x0006;
    let tcp_len: u16= get_tcp_length(ipv4hdr);

    let mut sum: u32 = 0;

    for w in [src_hi, src_lo, dst_hi, dst_lo, proto, tcp_len] {
        sum = add_carry(sum, w);
    }

    sum
}

fn get_tcp_length(ipv4hdr: *const Ipv4Hdr) -> u16 {
    let tot_len = unsafe { u16::from_be_bytes((*ipv4hdr).tot_len) };
    let ihl = (unsafe { (*ipv4hdr).vihl } & 0x0f) as u16 * 4;
    tot_len - ihl
}

fn get_tcp_csum(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let tcp_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let tcp_length = TcpHdr::LEN + 12 + WOOLONG_WORD_SLICE.len();
    let tcphdr: *const TcpHdr = ptr_at(ctx, tcp_offset)?;

    if start + tcp_offset + tcp_length > end {
        return Err(());
    }

    unsafe { (*(tcphdr as *mut TcpHdr)).check = [0, 0]; }

    let tcp_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcphdr as *mut u32,
            tcp_length as u32,
            0
        )
    };

    if tcp_sum < 0 {
        return Err(());
    }

    Ok(tcp_sum as u32)
}

fn recalc_tcp_csum(ctx: &XdpContext, ipv4hdr: *const Ipv4Hdr, tcphdr: *const TcpHdr) -> Result<(), ()> {
    let pseudo_sum = get_pseudo_header(ipv4hdr);
    let tcp_sum = get_tcp_csum(ctx)?;

    let total = pseudo_sum + tcp_sum;
    let csum = fold_csum(total);

    unsafe { (*(tcphdr as *mut TcpHdr)).check = csum.to_be_bytes(); }
    Ok(())
}

fn recalc_ipv4_csum(ipv4hdr: *const Ipv4Hdr) {
    unsafe { (*(ipv4hdr as *mut Ipv4Hdr)).check = [0, 0]; }
    let ihl_bytes = ((unsafe { (*ipv4hdr).vihl } & 0x0f) as usize) * 4;
    let csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            ipv4hdr as *mut u32,
            ihl_bytes as u32,
            0
        )
    };
    if csum >= 0 {
        let new = fold_csum(csum as u32).to_be_bytes();
        unsafe { (*(ipv4hdr as *mut Ipv4Hdr)).check = new };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
