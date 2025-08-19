use bytemuck::{Pod, Zeroable};

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C, packed)]
pub struct iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}
