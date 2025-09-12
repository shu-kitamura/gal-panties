#![no_std]

#[repr(C)]
pub struct Packet {
    pub data: [u8; 54],
    pub len: u32,
}