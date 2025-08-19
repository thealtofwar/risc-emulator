use bytemuck::NoUninit;

#[derive(NoUninit, Clone, Copy)]
#[repr(C, packed)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
