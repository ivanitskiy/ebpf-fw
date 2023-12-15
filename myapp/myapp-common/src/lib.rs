#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BackendPorts {
    pub ips: [u32; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendPorts {}
