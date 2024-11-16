use crate::transaction::Transaction;
use crate::utils::CompactBytes;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Block {
    /// The version number for the block.
    pub version: [u8; 4],
    /// The block hash of a previous block this block is building on top of.
    pub previous_block: [u8; 32],
    /// A fingerprint for all of the transactions included in the block.
    pub merkle_root: [u8; 32],
    /// The current time as a Unix timestamp.
    pub time: [u8; 4],
    /// A compact representation of the current target.
    pub bits: u8,
    /// How many upcoming transactions are included in the block.
    pub transaction_count: CompactBytes,
    /// All of the raw transactions included in the block concatenated together.
    pub transactions: Vec<Transaction>,
}
