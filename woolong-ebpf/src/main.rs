#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[xdp]
pub fn woolong(ctx: XdpContext) -> u32 {
    match try_woolong(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}


fn try_woolong(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ipv4hdr: *const Ipv4Hdr = get_ipv4hdr(&ctx, ethhdr).ok_or(())?;
    let tcphdr: *const TcpHdr = get_tcphdr(&ctx, ipv4hdr).ok_or(())?;

    let (source_port, dest_port) = get_ports(tcphdr);

    if source_port == 7777 {
        info!(&ctx, "SRC PORT: {}, DST PORT: {}", source_port, dest_port);
        swap_ports(tcphdr);
        let (swaped_source_port, swapped_dest_port) = get_ports(tcphdr);
        info!(&ctx, "SWAPED SRC PORT: {}, SWAPED DST PORT: {}", swaped_source_port, swapped_dest_port);
        // get_payload(&ctx)?;
        return Ok(xdp_action::XDP_TX);
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

// fn get_payload(ctx: &XdpContext) -> Result<&[u8], ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let total = end - start;
//     let payload_len = total - (EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN);

//     let payload_ptr: *const u8 = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN)?;
//     let payload: &[u8] = unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) };
//     Ok(payload)
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
