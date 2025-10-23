use crate::script::Script;
use crate::utils::CompactBytes;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct TransactionInput {
    /// The TXID of the transaction containing the output you want to spend.
    pub txid: [u8; 32],
    /// The index number of the output you want to spend.
    pub vout: [u8; 4],
    /// The size in bytes of the upcoming ScriptSig.
    pub script_sig_size: CompactBytes,
    /// The unlocking code for the output you want to spend.
    pub script_sig: Script,
    /// Set whether the transaction can be replaced or when it can be mined.
    pub sequence: [u8; 4],
}

impl Serialize for TransactionInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut t: Vec<u8> = vec![];
        t.extend(&self.txid);
        t.extend(&self.vout);
        t.extend(&self.script_sig_size.to_bytes());
        t.extend(self.script_sig.to_bytes());
        serializer.serialize_bytes(&t)
    }
}

impl<'de> Deserialize<'de> for TransactionInput {
    fn deserialize<D>(deserializer: D) -> Result<TransactionInput, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let txid: [u8; 32] = bytes[0..32].try_into().unwrap();
        let vout: [u8; 4] = bytes[32..36].try_into().unwrap();

        // Parse CompactBytes for script_sig_size
        let mut offset = 36;
        let first_byte = bytes[offset];
        let (script_sig_size, compact_size) = if first_byte < 0xFD {
            (CompactBytes::B1(first_byte), 1)
        } else if first_byte == 0xFD {
            (CompactBytes::B2([bytes[offset + 1], bytes[offset + 2]]), 3)
        } else if first_byte == 0xFE {
            (
                CompactBytes::B4([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]),
                5,
            )
        } else {
            (
                CompactBytes::B8([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                    bytes[offset + 8],
                ]),
                9,
            )
        };
        offset += compact_size;

        // Determine the actual size value from CompactBytes
        let script_size = match script_sig_size {
            CompactBytes::B1(b) => b as usize,
            CompactBytes::B2([b1, b2]) => u16::from_le_bytes([b1, b2]) as usize,
            CompactBytes::B4([b1, b2, b3, b4]) => u32::from_le_bytes([b1, b2, b3, b4]) as usize,
            CompactBytes::B8(b) => u64::from_le_bytes(b) as usize,
        };

        // Parse script_sig
        let script_bytes = bytes[offset..offset + script_size].to_vec();
        let script_sig = Script::of_bytes(script_bytes);
        offset += script_size;

        // Parse sequence
        let sequence: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();

        Ok(TransactionInput {
            txid,
            vout,
            script_sig_size,
            script_sig,
            sequence,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionOutput {
    /// The value of the output in satoshis.
    pub amount: u64,
    /// The size in bytes of the upcoming ScriptPubKey.
    pub script_sig_size: u8,
    /// The locking code for this output.
    pub script_sig: Script,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StackItem {
    /// The size of the upcoming stack item.
    pub size: CompactBytes,
    /// The data to be pushed on to the stack.
    pub item: Vec<u8>,
}

#[derive(Debug)]
pub struct Transaction {
    /// The version number for the transaction. Used to enable new features.
    pub version: [u8; 4],
    // /// Used to indicate a segwit transaction. Must be 00.
    // pub marker: u8,
    // /// Used to indicate a segwit transaction. Must be 01 or greater.
    // pub flag: u8,
    /// Indicates the number of inputs.
    pub input_count: CompactBytes,
    /// The transaction inputs.
    pub inputs: Vec<TransactionInput>,
    /// Indicates the number of outputs.
    pub output_count: CompactBytes,
    /// The transaction outputs.
    pub outputs: Vec<TransactionOutput>,
    // /// The first arg is the number of items to be pushed on to the stack as
    // /// part of the unlocking code.
    // /// The second arg is each stack iterm.
    // /// The list should be the same size than the number of outputs.
    // pub witnesses: Vec<(CompactBytes, StackItem)>,
    /// Set a time or height after which the transaction can be mined.
    pub lock_time: [u8; 4],
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut t: Vec<u8> = vec![];
        t.extend(&self.version);
        t.extend(&self.input_count.to_bytes());
        for input in &self.inputs {
            t.extend(bincode::serialize(input).unwrap());
        }
        t.extend(&self.output_count.to_bytes());
        for output in &self.outputs {
            t.extend(bincode::serialize(output).unwrap());
        }
        t.extend(&self.lock_time);
        serializer.serialize_bytes(&t)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Transaction, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let version: [u8; 4] = bytes[0..4].try_into().unwrap();

        // Parse input_count
        let mut offset = 4;
        let first_byte = bytes[offset];
        let (input_count, compact_size) = if first_byte < 0xFD {
            (CompactBytes::B1(first_byte), 1)
        } else if first_byte == 0xFD {
            (CompactBytes::B2([bytes[offset + 1], bytes[offset + 2]]), 3)
        } else if first_byte == 0xFE {
            (
                CompactBytes::B4([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]),
                5,
            )
        } else {
            (
                CompactBytes::B8([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                    bytes[offset + 8],
                ]),
                9,
            )
        };
        offset += compact_size;

        // Determine number of inputs
        let num_inputs = match input_count {
            CompactBytes::B1(b) => b as usize,
            CompactBytes::B2([b1, b2]) => u16::from_le_bytes([b1, b2]) as usize,
            CompactBytes::B4([b1, b2, b3, b4]) => u32::from_le_bytes([b1, b2, b3, b4]) as usize,
            CompactBytes::B8(b) => u64::from_le_bytes(b) as usize,
        };

        // Parse inputs
        let mut inputs = Vec::new();
        for _ in 0..num_inputs {
            // Each input needs custom parsing - we need to find where it ends
            // TransactionInput format:
            // - txid: 32 bytes
            // - vout: 4 bytes
            // - script_sig_size: CompactBytes
            // - script_sig: variable
            // - sequence: 4 bytes

            let txid: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
            offset += 32;
            let vout: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
            offset += 4;

            // Parse script_sig_size
            let first_byte = bytes[offset];
            let (script_sig_size, compact_size) = if first_byte < 0xFD {
                (CompactBytes::B1(first_byte), 1)
            } else if first_byte == 0xFD {
                (CompactBytes::B2([bytes[offset + 1], bytes[offset + 2]]), 3)
            } else if first_byte == 0xFE {
                (
                    CompactBytes::B4([
                        bytes[offset + 1],
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                    ]),
                    5,
                )
            } else {
                (
                    CompactBytes::B8([
                        bytes[offset + 1],
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                        bytes[offset + 7],
                        bytes[offset + 8],
                    ]),
                    9,
                )
            };
            offset += compact_size;

            let script_size = match script_sig_size {
                CompactBytes::B1(b) => b as usize,
                CompactBytes::B2([b1, b2]) => u16::from_le_bytes([b1, b2]) as usize,
                CompactBytes::B4([b1, b2, b3, b4]) => u32::from_le_bytes([b1, b2, b3, b4]) as usize,
                CompactBytes::B8(b) => u64::from_le_bytes(b) as usize,
            };

            let script_bytes = bytes[offset..offset + script_size].to_vec();
            let script_sig = Script::of_bytes(script_bytes);
            offset += script_size;

            let sequence: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
            offset += 4;

            inputs.push(TransactionInput {
                txid,
                vout,
                script_sig_size,
                script_sig,
                sequence,
            });
        }

        // Parse output_count
        let first_byte = bytes[offset];
        let (output_count, compact_size) = if first_byte < 0xFD {
            (CompactBytes::B1(first_byte), 1)
        } else if first_byte == 0xFD {
            (CompactBytes::B2([bytes[offset + 1], bytes[offset + 2]]), 3)
        } else if first_byte == 0xFE {
            (
                CompactBytes::B4([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]),
                5,
            )
        } else {
            (
                CompactBytes::B8([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                    bytes[offset + 8],
                ]),
                9,
            )
        };
        offset += compact_size;

        // Determine number of outputs
        let num_outputs = match output_count {
            CompactBytes::B1(b) => b as usize,
            CompactBytes::B2([b1, b2]) => u16::from_le_bytes([b1, b2]) as usize,
            CompactBytes::B4([b1, b2, b3, b4]) => u32::from_le_bytes([b1, b2, b3, b4]) as usize,
            CompactBytes::B8(b) => u64::from_le_bytes(b) as usize,
        };

        // Parse outputs
        let mut outputs = Vec::new();
        for _ in 0..num_outputs {
            // TransactionOutput format:
            // - amount: 8 bytes (u64 little endian)
            // - script_sig_size: 1 byte (u8)
            // - script_sig: variable

            let amount = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;

            let script_sig_size = bytes[offset];
            offset += 1;

            let script_bytes = bytes[offset..offset + script_sig_size as usize].to_vec();
            let script_sig = Script::of_bytes(script_bytes);
            offset += script_sig_size as usize;

            outputs.push(TransactionOutput {
                amount,
                script_sig_size,
                script_sig,
            });
        }

        // Parse lock_time
        let lock_time: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();

        Ok(Transaction {
            version,
            input_count,
            inputs,
            output_count,
            outputs,
            lock_time,
        })
    }
}

impl Transaction {
    // pub fn is_segregated_witness(&self) -> bool {
    //     self.marker == 0 && self.flag == 1
    // }

    pub fn of_bytes(bytes: Vec<u8>) -> Transaction {
        let length: u64 = bytes.len().try_into().unwrap();
        let mut bytes_with_length: Vec<u8> = length.to_le_bytes().to_vec();
        bytes_with_length.extend(bytes);
        bincode::deserialize(&bytes_with_length).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let tx = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
        let tx = hex::decode(tx).unwrap();
        let tx = Transaction::of_bytes(tx);
        println!("Tx: {:?}", tx);
    }
}
