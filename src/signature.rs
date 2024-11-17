use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Signature type hash/flags
#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureType {
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,

    /// Taproot only; implied when sighash byte is missing, and equivalent to
    /// SIGHASH_ALL
    SIGHASH_DEFAULT,
    SIGHASH_OUTPUT_MASK,
    SIGHASH_INPUT_MASK,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(Vec<u8>, SignatureType);

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut t: Vec<u8> = vec![];
        let sig_bytes = match self.1 {
            SignatureType::SIGHASH_ALL => 0x01,
            SignatureType::SIGHASH_NONE => 0x02,
            SignatureType::SIGHASH_SINGLE => 0x03,
            SignatureType::SIGHASH_ANYONECANPAY => 0x80,
            SignatureType::SIGHASH_DEFAULT
            | SignatureType::SIGHASH_OUTPUT_MASK
            | SignatureType::SIGHASH_INPUT_MASK => unimplemented!("Unsupported for now"),
        };
        t.extend_from_slice(&self.0);
        t.push(sig_bytes);
        serializer.serialize_bytes(&t)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let sig_type = match bytes.last() {
            Some(0x01) => SignatureType::SIGHASH_ALL,
            Some(0x02) => SignatureType::SIGHASH_NONE,
            Some(0x03) => SignatureType::SIGHASH_SINGLE,
            Some(0x80) => SignatureType::SIGHASH_ANYONECANPAY,
            _ => panic!("Invalid signature type"),
        };
        Ok(Signature(bytes[..bytes.len() - 1].to_vec(), sig_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;

    #[test]
    fn test_signature_serialize_deserialize() {
        let sig = "304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307";
        let sig = Signature(hex::decode(sig).unwrap(), SignatureType::SIGHASH_ALL);
        let encoded_sig = bincode::serialize(&sig).unwrap();
        let decoded_sig: Signature = bincode::deserialize(&encoded_sig).unwrap();
        assert_eq!(decoded_sig, sig);
    }
}
