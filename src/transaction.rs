use crate::script::Script;

pub struct TransactionInput {
    /// The TXID of the transaction containing the output you want to spend.
    pub txid: [u8; 32],
    /// The index number of the output you want to spend.
    pub vout: [u8; 4],
    // FIXME: should be a compact size
    /// The size in bytes of the upcoming ScriptSig.
    pub script_sig_size: u8,
    /// The unlocking code for the output you want to spend.
    pub script_sig: Script,
    /// Set whether the transaction can be replaced or when it can be mined.
    pub sequence: [u8; 4],
}

pub struct TransactionOutput {
    /// The value of the output in satoshis.
    pub amount: u64,
    /// The size in bytes of the upcoming ScriptPubKey.
    pub script_sig_size: u8,
    /// The locking code for this output.
    pub script_sig: Script,
}

pub struct StackItem {
    // FIXME: should be a compact size
    /// The size of the upcoming stack item.
    pub size: u8,
    /// The data to be pushed on to the stack.
    pub item: Vec<u8>,
}

pub struct Transaction {
    /// The version number for the transaction. Used to enable new features.
    pub version: [u8; 4],
    /// Used to indicate a segwit transaction. Must be 00.
    pub marker: u8,
    /// Used to indicate a segwit transaction. Must be 01 or greater.
    pub flag: u8,
    /// Indicates the number of inputs.
    // FIXME: should be a compact size
    pub input_count: u8,
    pub outputs: Vec<TransactionOutput>,
    // FIXME: first arg should be a compact size
    /// The first arg is the number of items to be pushed on to the stack as
    /// part of the unlocking code.
    /// The second arg is each stack iterm.
    /// The list should be the same size than the number of outputs.
    pub witnesses: Vec<(u8, StackItem)>,
    /// Set a time or height after which the transaction can be mined.
    pub lock_tim: [u8; 4],
}
