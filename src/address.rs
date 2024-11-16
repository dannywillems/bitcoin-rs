/// Implement the different type of Bitcoin addresses
pub enum Address {
    P2PKH(String),
    P2SH(String),
}
