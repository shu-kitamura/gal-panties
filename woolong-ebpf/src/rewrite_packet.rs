use aya_ebpf::programs::XdpContext;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

use crate::{add_carry, fold_csum, get_data_length, ptr_at};

const TCP_PROTO_TYPE: u16 = 0x0006;

pub fn swap_macaddrs(ethhdr: *const EthHdr) {
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    unsafe {
        (*(ethhdr as *mut EthHdr)).src_addr = dst_mac;
    }
    unsafe {
        (*(ethhdr as *mut EthHdr)).dst_addr = src_mac;
    }
}

pub fn swap_ipv4addrs(ipv4hdr: *const Ipv4Hdr) {
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    unsafe {
        (*(ipv4hdr as *mut Ipv4Hdr)).src_addr = dst_ip;
    }
    unsafe {
        (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = src_ip;
    }
}

pub fn swap_ports(tcphdr: *const TcpHdr) {
    let src_port = unsafe { (*tcphdr).source };
    let dst_port = unsafe { (*tcphdr).dest };

    unsafe {
        (*(tcphdr as *mut TcpHdr)).source = dst_port;
    }
    unsafe {
        (*(tcphdr as *mut TcpHdr)).dest = src_port;
    }
}

pub fn rewrite_payload(
    ctx: &XdpContext,
    ipv4hdr: *const Ipv4Hdr,
    tcphdr: *const TcpHdr,
    new: &[u8],
) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
    let payload_length = get_data_length(ipv4hdr, tcphdr);
    let ptr: *const u8 = ptr_at(ctx, payload_offset)?;

    if new.len() != payload_length {
        return Err(());
    }

    if start + payload_offset + payload_length > end {
        return Err(());
    }

    let mut i = 0;
    while i < payload_length {
        let np = unsafe { *new.get_unchecked(i) };
        unsafe {
            core::ptr::write_unaligned((ptr as *mut u8).wrapping_add(i), np);
        }
        i += 1;
    }
    Ok(())
}

pub fn rewrite_seq_ack(ipv4hdr: *const Ipv4Hdr, tcphdr: *const TcpHdr) -> Result<(), ()> {
    let old_seq = u32::from_be_bytes(unsafe { (*tcphdr).seq });
    let old_ack = u32::from_be_bytes(unsafe { (*tcphdr).ack_seq });

    let payload_length = get_data_length(ipv4hdr, tcphdr);

    let syn = unsafe { (*tcphdr).syn() != 0 };
    let fin = unsafe { (*tcphdr).fin() != 0 };
    let inc = payload_length + if syn { 1 } else { 0 } + if fin { 1 } else { 0 };

    let new_seq = old_ack;
    let new_ack = old_seq.wrapping_add(inc as u32);

    unsafe {
        (*(tcphdr as *mut TcpHdr)).seq = new_seq.to_be_bytes();
    }
    unsafe {
        (*(tcphdr as *mut TcpHdr)).ack_seq = new_ack.to_be_bytes();
    }
    Ok(())
}

pub fn rewrite_flags(tcphdr: *const TcpHdr) -> Result<(), ()> {
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
    let proto: u16 = TCP_PROTO_TYPE;
    let tcp_len: u16 = get_tcp_length(ipv4hdr);

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

// TODO: 汚いコードになっている
fn get_tcp_csum(ctx: &XdpContext, ipv4hdr: *const Ipv4Hdr) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let tcp_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let tcp_length = get_tcp_length(ipv4hdr) as usize;
    let tcphdr: *const TcpHdr = ptr_at(ctx, tcp_offset)?;

    if start + tcp_offset + tcp_length > end {
        return Err(());
    }

    unsafe {
        (*(tcphdr as *mut TcpHdr)).check = [0, 0];
    }

    let mut i: usize = 0;
    let mut csum: u32 = 0;
    while i < tcp_length && i < 1000 {
        // 1バイト目
        let p0: *const u8 = ptr_at(ctx, tcp_offset + i)?;
        let b0 = unsafe { core::ptr::read(p0) } as u32;
        i += 1;

        // 2バイト目があれば読む、なければ 0 パディング
        let b1 = if i < tcp_length {
            let p1: *const u8 = ptr_at(ctx, tcp_offset + i)?;
            let v = unsafe { core::ptr::read(p1) } as u32;
            i += 1;
            v
        } else {
            0
        };

        // ここで“数値”として 16bit big-endian を合成
        let w = ((b0 << 8) | b1) as u16;
        csum = add_carry(csum, w);
    }
    Ok(csum)
}

pub fn recalc_tcp_csum(
    ctx: &XdpContext,
    ipv4hdr: *const Ipv4Hdr,
    tcphdr: *const TcpHdr,
) -> Result<(), ()> {
    let pseudo_sum = get_pseudo_header(ipv4hdr);
    let tcp_sum = get_tcp_csum(ctx, ipv4hdr)?;

    unsafe {
        (*(tcphdr as *mut TcpHdr)).check = [0, 0];
    }

    let total = pseudo_sum + tcp_sum;
    let csum: u16 = fold_csum(total);

    unsafe {
        (*(tcphdr as *mut TcpHdr)).check = csum.to_be_bytes();
    }
    Ok(())
}
