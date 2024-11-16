/// Signature type hash/flags
#[allow(non_camel_case_types, non_snake_case)]
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
