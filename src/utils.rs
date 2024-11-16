use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A compact size field is used in network messages to indicate the size of an
/// upcoming field or the number of upcoming fields.
/// It can store numbers between 0 and 18446744073709551615.
/// The size of the field increases as the number it contains increases. Or in
/// other words, smaller numbers take up less space. This means you don't have
/// to use a larger fixed-size field at all times to accommodate the largest
/// acceptable number.
#[derive(Debug, PartialEq, Eq)]
pub enum CompactBytes {
    B1(u8),
    B2([u8; 2]),
    B4([u8; 4]),
    B8([u8; 8]),
}

impl From<Vec<u8>> for CompactBytes {
    fn from(s: Vec<u8>) -> CompactBytes {
        if s.len() == 1 {
            CompactBytes::B1(s[0])
        } else if s.len() == 3 {
            assert_eq!(s[0], 0xFD, "The leading byte must be 0xFD");
            CompactBytes::B2([s[1], s[2]])
        } else if s.len() == 5 {
            assert_eq!(s[0], 0xFE, "The leading byte must be 0xFE");
            CompactBytes::B4([s[1], s[2], s[3], s[4]])
        } else if s.len() == 9 {
            assert_eq!(s[0], 0xFF, "The leading byte must be 0xFF");
            CompactBytes::B8([s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8]])
        } else {
            panic!("Unsupported number of bytes")
        }
    }
}

impl Serialize for CompactBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let res = match self {
            CompactBytes::B1(b) => vec![*b],
            CompactBytes::B2(b) => vec![0xFD, b[0], b[1]],
            CompactBytes::B4(b) => vec![0xFE, b[0], b[1], b[2], b[3]],
            CompactBytes::B8(b) => vec![0xFF, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
        };
        serializer.serialize_bytes(&res)
    }
}

// FIXME: handle correctly the error instead of panicking
impl<'de> Deserialize<'de> for CompactBytes {
    fn deserialize<D>(deserializer: D) -> Result<CompactBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Vec::<u8>::deserialize(deserializer)?;
        if s.len() == 1 {
            Ok(CompactBytes::B1(s[0]))
        } else if s.len() == 3 {
            assert_eq!(s[0], 0xFD, "The leading byte must be 0xFD");
            Ok(CompactBytes::B2([s[1], s[2]]))
        } else if s.len() == 5 {
            assert_eq!(s[0], 0xFE, "The leading byte must be 0xFE");
            Ok(CompactBytes::B4([s[1], s[2], s[3], s[4]]))
        } else if s.len() == 9 {
            assert_eq!(s[0], 0xFF, "The leading byte must be 0xFF");
            Ok(CompactBytes::B8([
                s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8],
            ]))
        } else {
            panic!("Unsupported number of bytes")
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_serialize_deserialize() {
        {
            let b1 = CompactBytes::B1(0x01);
            let serialize = bincode::serialize(&b1).unwrap();
            let deserialize: CompactBytes = bincode::deserialize(&serialize).unwrap();
            assert_eq!(b1, deserialize);
        }
        {
            let b2 = CompactBytes::B2([0x01, 0x02]);
            let serialize = bincode::serialize(&b2).unwrap();
            let deserialize: CompactBytes = bincode::deserialize(&serialize).unwrap();
            assert_eq!(b2, deserialize);
        }
        {
            let b4 = CompactBytes::B4([0x01, 0x02, 0x03, 0x04]);
            let serialize = bincode::serialize(&b4).unwrap();
            let deserialize: CompactBytes = bincode::deserialize(&serialize).unwrap();
            assert_eq!(b4, deserialize);
        }
        {
            let b8 = CompactBytes::B8([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
            let serialize = bincode::serialize(&b8).unwrap();
            let deserialize: CompactBytes = bincode::deserialize(&serialize).unwrap();
            assert_eq!(b8, deserialize);
        }
    }
}
