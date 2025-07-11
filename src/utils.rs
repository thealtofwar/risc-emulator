pub trait FromSlice {
    fn from_slice(slice: &[u8]) -> Self;
}

macro_rules! impl_from_slice {
    ($($t:ty),*) => {
        $(
            impl FromSlice for $t {
                fn from_slice(slice: &[u8]) -> Self {
                    Self::from_le_bytes(slice.try_into().expect("Incorrect length"))
                }
            }
        )*
    };
}

impl_from_slice!(u8, u16, u32, u64, i8, i16, i32, i64);

pub trait SignExtend {
    /// Convert signed integer to a sign-extended i64. Ported from raki
    /// # Arguments
    /// * `self` - The value to be converted.
    /// * `bit_size` - Bit width to be converted.
    fn sign_ext(self, bit_size: u32) -> i64;
}

macro_rules! impl_sign_extend {
    ($($t:ty),*) => {
        $(
            impl SignExtend for $t {
                fn sign_ext(self, bit_size: u32) -> i64 {
                    let imm32 = self as i64 & (2_i64.pow(bit_size) - 1);
                    if imm32 >> (bit_size - 1) & 0x1 == 1 {
                        imm32 - 2_i64.pow(bit_size)
                    } else {
                        imm32
                    }
                }
            }
        )*
    };
}

impl_sign_extend!(i8, i16, i32, i64);
