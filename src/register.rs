use std::fmt::LowerHex;

#[derive(Copy, Clone, Default, PartialEq)]
pub struct Register {
    pub value: [u8; 8],
}

impl Register {
    pub fn put_i64(&mut self, value: i64) {
        self.value = value.to_le_bytes()
    }
    pub fn get_i64(&self) -> i64 {
        i64::from_le_bytes(self.value)
    }
    pub fn incr_i64(&mut self, value: i64) {
        self.put_i64(self.get_i64() + value);
    }
    pub fn put_u64(&mut self, value: u64) {
        self.value = value.to_le_bytes()
    }
    pub fn get_u64(&self) -> u64 {
        u64::from_le_bytes(self.value)
    }
    pub fn incr_u64(&mut self, value: u64) {
        self.put_u64(self.get_u64() + value);
    }
}

impl LowerHex for Register {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // GDB info register style representation of the value
        write!(f, "{:x}", u64::from_le_bytes(self.value))
    }
}

impl Eq for Register {}
