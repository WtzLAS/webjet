//! Checked reads of fixed-size fields from byte slices. They return `None`
//! when the slice is too short, so wire parsing never panics.

/// `N` bytes starting at `at`.
pub fn array<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..)?.first_chunk::<N>().copied()
}

pub fn be_u16(b: &[u8], at: usize) -> Option<u16> {
    array(b, at).map(u16::from_be_bytes)
}

pub fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    array(b, at).map(u32::from_be_bytes)
}

pub fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    array(b, at).map(u64::from_be_bytes)
}

/// The first eight bytes of a 32-byte id as a number (hashing, flow ids).
pub fn prefix_u64(id: &[u8; 32]) -> u64 {
    let (head, _) = id.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
    u64::from_be_bytes(*head)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads() {
        let b = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(be_u16(&b, 0), Some(0x0102));
        assert_eq!(be_u32(&b, 5), Some(0x06070809));
        assert_eq!(be_u32(&b, 6), None);
        assert_eq!(be_u64(&b, 1), Some(0x0203040506070809));
        assert_eq!(array::<2>(&b, 9), None);
        assert_eq!(array::<0>(&b, 9), Some([]));
        assert_eq!(array::<1>(&b, 10), None);
        assert_eq!(prefix_u64(&[0xff; 32]), u64::MAX);
    }
}
