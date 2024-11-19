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
        // FIXME
        Ok(TransactionInput {
            txid,
            vout,
            script_sig_size,
            script_sig,
            sequence: [0; 4],
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Transaction {
    /// The version number for the transaction. Used to enable new features.
    pub version: [u8; 4],
    // /// Used to indicate a segwit transaction. Must be 00.
    // pub marker: u8,
    // /// Used to indicate a segwit transaction. Must be 01 or greater.
    // pub flag: u8,
    /// Indicates the number of inputs.
    pub input_count: CompactBytes,
    pub outputs: Vec<TransactionOutput>,
    // /// The first arg is the number of items to be pushed on to the stack as
    // /// part of the unlocking code.
    // /// The second arg is each stack iterm.
    // /// The list should be the same size than the number of outputs.
    // pub witnesses: Vec<(CompactBytes, StackItem)>,
    /// Set a time or height after which the transaction can be mined.
    pub lock_time: [u8; 4],
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
