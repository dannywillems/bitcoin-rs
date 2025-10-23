//! This module provides an implementation of Bitcoin script

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::From;
use core::convert::Into;

use ripemd::Digest;
use ripemd::Ripemd160;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sha1::Sha1;
use sha2::Sha256;

/// Bitcoin Script execution stack
///
/// Bitcoin Script uses two stacks during execution:
/// - **main**: The primary stack where most operations occur
/// - **alt**: The alternate stack (altstack) for temporary storage
///
/// The altstack is accessed via OP_TOALTSTACK and OP_FROMALTSTACK opcodes,
/// allowing scripts to temporarily move data off the main stack.
#[derive(Clone)]
pub struct Stack {
    /// Main execution stack
    main: Vec<Vec<u8>>,
    /// Alternate stack for temporary storage
    alt: Vec<Vec<u8>>,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            main: vec![],
            alt: vec![],
        }
    }

    /// Push a value onto the main stack
    pub fn push(&mut self, v: Vec<u8>) {
        self.main.push(v)
    }

    /// Pop a value from the main stack
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.main.pop()
    }

    /// Pop a value from the main stack (panics if empty)
    pub fn pop_unwrap(&mut self) -> Vec<u8> {
        self.main.pop().unwrap()
    }

    /// Check if the main stack is empty
    pub fn is_empty(&self) -> bool {
        self.main.is_empty()
    }

    /// Get the number of elements on the main stack
    pub fn len(&self) -> usize {
        self.main.len()
    }

    /// Check if the main stack has at least n elements
    pub fn has(&self, n: usize) -> bool {
        self.main.len() >= n
    }

    /// Move top item from main stack to altstack (OP_TOALTSTACK)
    pub fn to_altstack(&mut self) {
        if let Some(v) = self.main.pop() {
            self.alt.push(v);
        }
    }

    /// Move top item from altstack to main stack (OP_FROMALTSTACK)
    pub fn from_altstack(&mut self) {
        if let Some(v) = self.alt.pop() {
            self.main.push(v);
        }
    }

    /// Check if the altstack has at least n elements
    pub fn has_alt(&self, n: usize) -> bool {
        self.alt.len() >= n
    }

    #[cfg(test)]
    pub fn debug(&self) {
        if self.is_empty() {
            println!("Stack is empty");
            return;
        }
        for elem in self.main.iter().rev() {
            let x = hex::encode(elem);
            println!("{}", x);
        }
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

// IMPROVEME: make a typed AST. I suggest to move it in `typed_script.rs`
#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // push value
    /// An empty array of bytes is pushed onto the stack. (This is not a no-op:
    /// an item is added to the stack.)
    OP_0,
    /// An empty array of bytes is pushed onto the stack. (This is not a no-op:
    /// an item is added to the stack.)
    OP_FALSE,
    /// The next opcode bytes is data to be pushed onto the stack
    OP_PUSHBYTES(u8),
    /// The next byte contains the number of bytes to be pushed onto the stack.
    OP_PUSHDATA1(u8),
    /// The next two bytes contain the number of bytes to be pushed onto the
    /// stack in little endian order.
    OP_PUSHDATA2([u8; 2]),
    /// The next four bytes contain the number of bytes to be pushed onto the
    /// stack in little endian order.
    OP_PUSHDATA4([u8; 4]),
    /// The number -1 is pushed onto the stack.
    OP_1NEGATE,
    /// Transaction is invalid unless occuring in an unexecuted OP_IF branch
    OP_RESERVED,
    /// The number 1 is pushed onto the stack.
    OP_1,
    /// The number 1 is pushed onto the stack.
    OP_TRUE,
    /// The number 2 is pushed onto the stack.
    OP_2,
    /// The number 3 is pushed onto the stack.
    OP_3,
    /// The number 4 is pushed onto the stack.
    OP_4,
    /// The number 5 is pushed onto the stack.
    OP_5,
    /// The number 6 is pushed onto the stack.
    OP_6,
    /// The number 7 is pushed onto the stack.
    OP_7,
    /// The number 8 is pushed onto the stack.
    OP_8,
    /// The number 9 is pushed onto the stack.
    OP_9,
    /// The number 10 is pushed onto the stack.
    OP_10,
    /// The number 11 is pushed onto the stack.
    OP_11,
    /// The number 12 is pushed onto the stack.
    OP_12,
    /// The number 13 is pushed onto the stack.
    OP_13,
    /// The number 14 is pushed onto the stack.
    OP_14,
    /// The number 15 is pushed onto the stack.
    OP_15,
    /// The number 16 is pushed onto the stack.
    OP_16,

    // control
    /// Does nothing
    OP_NOP,
    /// Transaction is invalid unless occuring in an unexecuted OP_IF branch
    OP_VER,
    /// If the top stack value is not False, the statements are executed. The
    /// top stack value is removed.
    OP_IF,
    /// If the top stack value is False, the statements are executed. The top
    /// stack value is removed.
    OP_NOTIF,
    /// Transaction is invalid even when occuring in an unexecuted OP_IF branch
    OP_VERIF,
    /// Transaction is invalid even when occuring in an unexecuted OP_IF branch
    OP_VERNOTIF,
    /// If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then
    /// these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE
    /// was executed then these statements are not.
    OP_ELSE,
    /// Ends an if/else block. All blocks must end, or the transaction is
    /// invalid. An OP_ENDIF without OP_IF earlier is also invalid.
    OP_ENDIF,
    /// Marks transaction as invalid if top stack value is not true. The top
    /// stack value is removed.
    OP_VERIFY,
    /// Marks transaction as invalid. Since bitcoin 0.9, a standard way of
    /// attaching extra data to transactions is to add a zero-value output with
    /// a scriptPubKey consisting of OP_RETURN followed by data. Such outputs
    /// are provably unspendable and specially discarded from storage in the
    /// UTXO set, reducing their cost to the network. Since 0.12, standard relay
    /// rules allow a single output with OP_RETURN, that contains any sequence
    /// of push statements (or `OP_RESERVED[1]`) after the OP_RETURN provided the
    /// total scriptPubKey length is at most 83 bytes.
    OP_RETURN,

    // stack ops
    /// Puts the input onto the top of the alt stack. Removes it from the main
    /// stack.
    OP_TOALTSTACK,
    /// Puts the input onto the top of the main stack. Removes it from the alt
    /// stack.
    OP_FROMALTSTACK,
    /// Removes the top two stack items.
    OP_2DROP,
    /// Duplicates the top two stack items.
    OP_2DUP,
    /// Duplicates the top three stack items.
    OP_3DUP,
    /// Copies the pair of items two spaces back in the stack to the front.
    OP_2OVER,
    /// The fifth and sixth items back are moved to the top of the stack.
    OP_2ROT,
    /// Swaps the top two pairs of items.
    OP_2SWAP,
    /// If the top stack value is not 0, duplicate it.
    OP_IFDUP,
    /// Puts the number of stack items onto the stack.
    OP_DEPTH,
    /// Removes the top stack item.
    OP_DROP,
    /// Duplicates the top stack item.
    OP_DUP,
    /// Removes the second-to-top stack item.
    OP_NIP,
    /// Copies the second-to-top stack item to the top.
    OP_OVER,
    /// The item n back in the stack is copied to the top.
    OP_PICK,
    /// The item n back in the stack is moved to the top.
    OP_ROLL,
    /// The 3rd item down the stack is moved to the top.
    OP_ROT,
    /// The top two items on the stack are swapped.
    OP_SWAP,
    /// The item at the top of the stack is copied and inserted before the
    /// second-to-top item.
    OP_TUCK,

    // splice ops
    /// Concatenates two strings. disabled.
    OP_CAT,
    /// Returns a section of a string. disabled.
    OP_SUBSTR,
    /// Keeps only characters left of the specified point in a string. disabled.
    OP_LEFT,
    /// Keeps only characters right of the specified point in a string.
    /// disabled.
    OP_RIGHT,
    /// Pushes the string length of the top element of the stack (without
    /// popping it).
    OP_SIZE,

    // bit logic
    /// Flips all of the bits in the input. disabled.
    OP_INVERT,
    /// Boolean and between each bit in the inputs. disabled.
    OP_AND,
    /// Boolean or between each bit in the inputs. disabled.
    OP_OR,
    /// Boolean exclusive or between each bit in the inputs. disabled.
    OP_XOR,
    /// Returns 1 if the inputs are exactly equal, 0 otherwise.
    OP_EQUAL,
    /// Same as OP_EQUAL, but runs OP_VERIFY afterward.
    OP_EQUALVERIFY,
    /// Transaction is invalid unless occuring in an unexecuted OP_IF branch
    OP_RESERVED1,
    /// Transaction is invalid unless occuring in an unexecuted OP_IF branch
    OP_RESERVED2,

    // numeric
    /// 1 is added to the input.
    OP_1ADD,
    /// 1 is subtracted from the input.
    OP_1SUB,
    /// The input is multiplied by 2. Currently disabled.
    OP_2MUL,
    /// The input is divided by 2. Currently disabled.
    OP_2DIV,
    /// The sign of the input is flipped.
    OP_NEGATE,
    /// The input is made positive.
    OP_ABS,
    /// If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    OP_NOT,
    /// Returns 0 if the input is 0. 1 otherwise.
    OP_0NOTEQUAL,

    /// a is added to b.
    OP_ADD,
    /// b is subtracted from a.
    OP_SUB,
    /// a is multiplied by b.
    OP_MUL,
    /// a is divided by b.
    OP_DIV,
    /// Returns the remainder after dividing a by b.
    OP_MOD,
    /// Shifts a left b bits, preserving sign.
    OP_LSHIFT,
    /// Shifts a right b bits, preserving sign.
    OP_RSHIFT,

    /// If both a and b are not 0, the output is 1. Otherwise 0.
    OP_BOOLAND,
    /// If a or b is not 0, the output is 1. Otherwise 0.
    OP_BOOLOR,
    /// Returns 1 if the numbers are equal, 0 otherwise.
    OP_NUMEQUAL,
    /// Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    OP_NUMEQUALVERIFY,
    /// Returns 1 if the numbers are not equal, 0 otherwise.
    OP_NUMNOTEQUAL,
    /// Returns 1 if a is less than b, 0 otherwise.
    OP_LESSTHAN,
    /// Returns 1 if a is greater than b, 0 otherwise.
    OP_GREATERTHAN,
    /// Returns 1 if a is less than or equal to b, 0 otherwise.
    OP_LESSTHANOREQUAL,
    /// Returns 1 if a is greater than or equal to b, 0 otherwise.
    OP_GREATERTHANOREQUAL,
    /// Returns the smaller of a and b.
    OP_MIN,
    /// Returns the larger of a and b.
    OP_MAX,
    /// Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    OP_WITHIN,

    // crypto
    /// The input is hashed using RIPEMD-160.
    OP_RIPEMD160,
    /// The input is hashed using SHA-1.
    OP_SHA1,
    /// The input is hashed using SHA-256.
    OP_SHA256,
    /// The input is hashed twice: first with SHA-256 and then with RIPEMD-160
    OP_HASH160,
    /// The input is hashed two times with SHA-256
    OP_HASH256,
    /// All of the signature checking words will only match signatures to the
    /// data after the most recently-executed OP_CODESEPARATOR
    OP_CODESEPARATOR,
    /// The entire transaction's outputs, inputs, and script (from the most
    /// recently-executed OP_CODESEPARATOR to the end) are hashed. The signature
    /// used by OP_CHECKSIG must be a valid signature for this hash and public key.
    /// If it is, 1 is returned, 0 otherwise
    OP_CHECKSIG,
    /// Same as OP_CHECKSIG, but OP_VERIFY is executed afterward
    OP_CHECKSIGVERIFY,
    /// Compares the first signature against each public key until it finds an
    /// ECDSA match. Starting with the subsequent public key, it compares the
    /// second signature against each remaining public key until it finds an
    /// ECDSA match. The process is repeated until all signatures have been
    /// checked or not enough public keys remain to produce a successful result.
    /// All signatures need to match a public key. Because public keys are not
    /// checked again if they fail any signature comparison, signatures must be
    /// placed in the scriptSig using the same order as their corresponding
    /// public keys were placed in the scriptPubKey or redeemScript. If all
    /// signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one
    /// extra unused value is removed from the stack.
    OP_CHECKMULTISIG,
    /// Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
    OP_CHECKMULTISIGVERIFY,

    // expansion
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP1,
    /// Marks transaction as invalid if the top stack item is greater than the
    /// transaction's nLockTime field, otherwise script evaluation continues as
    /// though an OP_NOP was executed. Transaction is also invalid if 1. the
    /// stack is empty; or 2. the top stack item is negative; or 3. the top
    /// stack item is greater than or equal to 500000000 while the transaction's
    /// nLockTime field is less than 500000000, or vice versa; or 4. the input's
    /// nSequence field is equal to 0xffffffff. The precise semantics are
    /// described in [BIP
    /// 0065](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).
    OP_CHECKLOCKTIMEVERIFY,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP2,
    /// Marks transaction as invalid if the relative lock time of the input
    /// (enforced by [BIP
    /// 0068](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)
    /// with nSequence) is not equal to or longer than the
    /// value of the top stack item. The precise semantics are described in [BIP
    /// 0112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki).
    OP_CHECKSEQUENCEVERIFY,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP3,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP4,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP5,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP6,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP7,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP8,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP9,
    /// The word is ignored. Does not mark transaction as invalid.
    OP_NOP10,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD,

    OP_INVALIDOPCODE,
}

// FIXME: ignore if riscv32i
impl core::fmt::Display for Opcode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            // push value
            Opcode::OP_0 => write!(f, "OP_0"),
            Opcode::OP_FALSE => write!(f, "OP_FALSE"),
            Opcode::OP_PUSHBYTES(x) => write!(f, "OP_PUSHBYTES{}", x),
            Opcode::OP_PUSHDATA1(x) => write!(f, "OP_PUSHDATA1 {:x?}", x),
            Opcode::OP_PUSHDATA2([x1, x2]) => write!(f, "OP_PUSHDATA2 {:x?}{:x?}", x1, x2),
            Opcode::OP_PUSHDATA4([x1, x2, x3, x4]) => {
                write!(f, "OP_PUSHDATA4 {:x?}{:x?}{:x?}{:x?}", x1, x2, x3, x4)
            }
            Opcode::OP_1NEGATE => write!(f, "OP_1NEGATE"),
            Opcode::OP_RESERVED => write!(f, "OP_RESERVED"),
            Opcode::OP_1 => write!(f, "OP_1"),
            Opcode::OP_TRUE => write!(f, "OP_TRUE"),
            Opcode::OP_2 => write!(f, "OP_2"),
            Opcode::OP_3 => write!(f, "OP_3"),
            Opcode::OP_4 => write!(f, "OP_4"),
            Opcode::OP_5 => write!(f, "OP_5"),
            Opcode::OP_6 => write!(f, "OP_6"),
            Opcode::OP_7 => write!(f, "OP_7"),
            Opcode::OP_8 => write!(f, "OP_8"),
            Opcode::OP_9 => write!(f, "OP_9"),
            Opcode::OP_10 => write!(f, "OP_10"),
            Opcode::OP_11 => write!(f, "OP_11"),
            Opcode::OP_12 => write!(f, "OP_12"),
            Opcode::OP_13 => write!(f, "OP_13"),
            Opcode::OP_14 => write!(f, "OP_14"),
            Opcode::OP_15 => write!(f, "OP_15"),
            Opcode::OP_16 => write!(f, "OP_16"),

            // control
            Opcode::OP_NOP => write!(f, "OP_NOP"),
            Opcode::OP_VER => write!(f, "OP_VER"),
            Opcode::OP_IF => write!(f, "OP_IF"),
            Opcode::OP_NOTIF => write!(f, "OP_NOTIF"),
            Opcode::OP_VERIF => write!(f, "OP_VERIF"),
            Opcode::OP_VERNOTIF => write!(f, "OP_VERNOTIF"),
            Opcode::OP_ELSE => write!(f, "OP_ELSE"),
            Opcode::OP_ENDIF => write!(f, "OP_ENDIF"),
            Opcode::OP_VERIFY => write!(f, "OP_VERIFY"),
            Opcode::OP_RETURN => write!(f, "OP_RETURN"),

            // stack ops
            Opcode::OP_TOALTSTACK => write!(f, "OP_TOALTSTACK"),
            Opcode::OP_FROMALTSTACK => write!(f, "OP_FROMALTSTACK"),
            Opcode::OP_2DROP => write!(f, "OP_2DROP"),
            Opcode::OP_2DUP => write!(f, "OP_2DUP"),
            Opcode::OP_3DUP => write!(f, "OP_3DUP"),
            Opcode::OP_2OVER => write!(f, "OP_2OVER"),
            Opcode::OP_2ROT => write!(f, "OP_2ROT"),
            Opcode::OP_2SWAP => write!(f, "OP_2SWAP"),
            Opcode::OP_IFDUP => write!(f, "OP_IFDUP"),
            Opcode::OP_DEPTH => write!(f, "OP_DEPTH"),
            Opcode::OP_DROP => write!(f, "OP_DROP"),
            Opcode::OP_DUP => write!(f, "OP_DUP"),
            Opcode::OP_NIP => write!(f, "OP_NIP"),
            Opcode::OP_OVER => write!(f, "OP_OVER"),
            Opcode::OP_PICK => write!(f, "OP_PICK"),
            Opcode::OP_ROLL => write!(f, "OP_ROLL"),
            Opcode::OP_ROT => write!(f, "OP_ROT"),
            Opcode::OP_SWAP => write!(f, "OP_SWAP"),
            Opcode::OP_TUCK => write!(f, "OP_TUCK"),

            // splice ops
            Opcode::OP_CAT => write!(f, "OP_CAT"),
            Opcode::OP_SUBSTR => write!(f, "OP_SUBSTR"),
            Opcode::OP_LEFT => write!(f, "OP_LEFT"),
            Opcode::OP_RIGHT => write!(f, "OP_RIGHT"),
            Opcode::OP_SIZE => write!(f, "OP_SIZE"),

            // bit logic
            Opcode::OP_INVERT => write!(f, "OP_INVERT"),
            Opcode::OP_AND => write!(f, "OP_AND"),
            Opcode::OP_OR => write!(f, "OP_OR"),
            Opcode::OP_XOR => write!(f, "OP_XOR"),
            Opcode::OP_EQUAL => write!(f, "OP_EQUAL"),
            Opcode::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
            Opcode::OP_RESERVED1 => write!(f, "OP_RESERVED1"),
            Opcode::OP_RESERVED2 => write!(f, "OP_RESERVED2"),

            // numeric
            Opcode::OP_1ADD => write!(f, "OP_1ADD"),
            Opcode::OP_1SUB => write!(f, "OP_1SUB"),
            Opcode::OP_2MUL => write!(f, "OP_2MUL"),
            Opcode::OP_2DIV => write!(f, "OP_2DIV"),
            Opcode::OP_NEGATE => write!(f, "OP_NEGATE"),
            Opcode::OP_ABS => write!(f, "OP_ABS"),
            Opcode::OP_NOT => write!(f, "OP_NOT"),
            Opcode::OP_0NOTEQUAL => write!(f, "OP_0NOTEQUAL"),

            Opcode::OP_ADD => write!(f, "OP_ADD"),
            Opcode::OP_SUB => write!(f, "OP_SUB"),
            Opcode::OP_MUL => write!(f, "OP_MUL"),
            Opcode::OP_DIV => write!(f, "OP_DIV"),
            Opcode::OP_MOD => write!(f, "OP_MOD"),
            Opcode::OP_LSHIFT => write!(f, "OP_LSHIFT"),
            Opcode::OP_RSHIFT => write!(f, "OP_RSHIFT"),

            Opcode::OP_BOOLAND => write!(f, "OP_BOOLAND"),
            Opcode::OP_BOOLOR => write!(f, "OP_BOOLOR"),
            Opcode::OP_NUMEQUAL => write!(f, "OP_NUMEQUAL"),
            Opcode::OP_NUMEQUALVERIFY => write!(f, "OP_NUMEQUALVERIFY"),
            Opcode::OP_NUMNOTEQUAL => write!(f, "OP_NUMNOTEQUAL"),
            Opcode::OP_LESSTHAN => write!(f, "OP_LESSTHAN"),
            Opcode::OP_GREATERTHAN => write!(f, "OP_GREATERTHAN"),
            Opcode::OP_LESSTHANOREQUAL => write!(f, "OP_LESSTHANOREQUAL"),
            Opcode::OP_GREATERTHANOREQUAL => write!(f, "OP_GREATERTHANOREQUAL"),
            Opcode::OP_MIN => write!(f, "OP_MIN"),
            Opcode::OP_MAX => write!(f, "OP_MAX"),

            Opcode::OP_WITHIN => write!(f, "OP_WITHIN"),

            // crypto
            Opcode::OP_RIPEMD160 => write!(f, "OP_RIPEMD160"),
            Opcode::OP_SHA1 => write!(f, "OP_SHA1"),
            Opcode::OP_SHA256 => write!(f, "OP_SHA256"),
            Opcode::OP_HASH160 => write!(f, "OP_HASH160"),
            Opcode::OP_HASH256 => write!(f, "OP_HASH256"),
            Opcode::OP_CODESEPARATOR => write!(f, "OP_CODESEPARATOR"),
            Opcode::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            Opcode::OP_CHECKSIGVERIFY => write!(f, "OP_CHECKSIGVERIFY"),
            Opcode::OP_CHECKMULTISIG => write!(f, "OP_CHECKMULTISIG"),
            Opcode::OP_CHECKMULTISIGVERIFY => write!(f, "OP_CHECKMULTISIGVERIFY"),

            // expansion
            Opcode::OP_NOP1 => write!(f, "OP_NOP1"),
            Opcode::OP_CHECKLOCKTIMEVERIFY => write!(f, "OP_CHECKLOCKTIMEVERIFY"),
            Opcode::OP_NOP2 => write!(f, "OP_NOP2"),
            Opcode::OP_CHECKSEQUENCEVERIFY => write!(f, "OP_CHECKSEQUENCEVERIFY"),
            Opcode::OP_NOP3 => write!(f, "OP_NOP3"),
            Opcode::OP_NOP4 => write!(f, "OP_NOP4"),
            Opcode::OP_NOP5 => write!(f, "OP_NOP5"),
            Opcode::OP_NOP6 => write!(f, "OP_NOP6"),
            Opcode::OP_NOP7 => write!(f, "OP_NOP7"),
            Opcode::OP_NOP8 => write!(f, "OP_NOP8"),
            Opcode::OP_NOP9 => write!(f, "OP_NOP9"),
            Opcode::OP_NOP10 => write!(f, "OP_NOP10"),

            // Opcode added by BIP 342 (Tapscript)
            Opcode::OP_CHECKSIGADD => write!(f, "OP_CHECKSIGADD"),

            Opcode::OP_INVALIDOPCODE => write!(f, "OP_INVALIDOPCODE"),
        }
    }
}

impl From<u8> for Opcode {
    fn from(val: u8) -> Opcode {
        match val {
            0x00 => Opcode::OP_0,
            x if (0x01..=0x4b).contains(&x) => Opcode::OP_PUSHBYTES(x),
            // Note that the value won't be correct as it depends on the next
            // bytes
            // Considered alone, the OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4
            // instructions are not correctly decoded from u8
            0x4c => Opcode::OP_PUSHDATA1(0),
            0x4d => Opcode::OP_PUSHDATA2([0, 0]),
            0x4e => Opcode::OP_PUSHDATA4([0, 0, 0, 0]),
            0x4f => Opcode::OP_1NEGATE,
            0x50 => Opcode::OP_RESERVED,
            0x51 => Opcode::OP_1,
            0x52 => Opcode::OP_2,
            0x53 => Opcode::OP_3,
            0x54 => Opcode::OP_4,
            0x55 => Opcode::OP_5,
            0x56 => Opcode::OP_6,
            0x57 => Opcode::OP_7,
            0x58 => Opcode::OP_8,
            0x59 => Opcode::OP_9,
            0x5a => Opcode::OP_10,
            0x5b => Opcode::OP_11,
            0x5c => Opcode::OP_12,
            0x5d => Opcode::OP_13,
            0x5e => Opcode::OP_14,
            0x5f => Opcode::OP_15,
            0x60 => Opcode::OP_16,

            // control
            0x61 => Opcode::OP_NOP,
            0x62 => Opcode::OP_VER,
            0x63 => Opcode::OP_IF,
            0x64 => Opcode::OP_NOTIF,
            0x65 => Opcode::OP_VERIF,
            0x66 => Opcode::OP_VERNOTIF,
            0x67 => Opcode::OP_ELSE,
            0x68 => Opcode::OP_ENDIF,
            0x69 => Opcode::OP_VERIFY,
            0x6a => Opcode::OP_RETURN,

            // stack ops
            0x6b => Opcode::OP_TOALTSTACK,
            0x6c => Opcode::OP_FROMALTSTACK,
            0x6d => Opcode::OP_2DROP,
            0x6e => Opcode::OP_2DUP,
            0x6f => Opcode::OP_3DUP,
            0x70 => Opcode::OP_2OVER,
            0x71 => Opcode::OP_2ROT,
            0x72 => Opcode::OP_2SWAP,
            0x73 => Opcode::OP_IFDUP,
            0x74 => Opcode::OP_DEPTH,
            0x75 => Opcode::OP_DROP,
            0x76 => Opcode::OP_DUP,
            0x77 => Opcode::OP_NIP,
            0x78 => Opcode::OP_OVER,
            0x79 => Opcode::OP_PICK,
            0x7a => Opcode::OP_ROLL,
            0x7b => Opcode::OP_ROT,
            0x7c => Opcode::OP_SWAP,
            0x7d => Opcode::OP_TUCK,

            // splice ops
            0x7e => Opcode::OP_CAT,
            0x7f => Opcode::OP_SUBSTR,
            0x80 => Opcode::OP_LEFT,
            0x81 => Opcode::OP_RIGHT,
            0x82 => Opcode::OP_SIZE,

            // bit logic
            0x83 => Opcode::OP_INVERT,
            0x84 => Opcode::OP_AND,
            0x85 => Opcode::OP_OR,
            0x86 => Opcode::OP_XOR,
            0x87 => Opcode::OP_EQUAL,
            0x88 => Opcode::OP_EQUALVERIFY,
            0x89 => Opcode::OP_RESERVED1,
            0x8a => Opcode::OP_RESERVED2,

            // numeric
            0x8b => Opcode::OP_1ADD,
            0x8c => Opcode::OP_1SUB,
            0x8d => Opcode::OP_2MUL,
            0x8e => Opcode::OP_2DIV,
            0x8f => Opcode::OP_NEGATE,
            0x90 => Opcode::OP_ABS,
            0x91 => Opcode::OP_NOT,
            0x92 => Opcode::OP_0NOTEQUAL,
            0x93 => Opcode::OP_ADD,
            0x94 => Opcode::OP_SUB,
            0x95 => Opcode::OP_MUL,
            0x96 => Opcode::OP_DIV,
            0x97 => Opcode::OP_MOD,
            0x98 => Opcode::OP_LSHIFT,
            0x99 => Opcode::OP_RSHIFT,
            0x9a => Opcode::OP_BOOLAND,
            0x9b => Opcode::OP_BOOLOR,
            0x9c => Opcode::OP_NUMEQUAL,
            0x9d => Opcode::OP_NUMEQUALVERIFY,
            0x9e => Opcode::OP_NUMNOTEQUAL,
            0x9f => Opcode::OP_LESSTHAN,
            0xa0 => Opcode::OP_GREATERTHAN,
            0xa1 => Opcode::OP_LESSTHANOREQUAL,
            0xa2 => Opcode::OP_GREATERTHANOREQUAL,
            0xa3 => Opcode::OP_MIN,
            0xa4 => Opcode::OP_MAX,

            0xa5 => Opcode::OP_WITHIN,

            // crypto
            0xa6 => Opcode::OP_RIPEMD160,
            0xa7 => Opcode::OP_SHA1,
            0xa8 => Opcode::OP_SHA256,
            0xa9 => Opcode::OP_HASH160,
            0xaa => Opcode::OP_HASH256,
            0xab => Opcode::OP_CODESEPARATOR,
            0xac => Opcode::OP_CHECKSIG,
            0xad => Opcode::OP_CHECKSIGVERIFY,
            0xae => Opcode::OP_CHECKMULTISIG,
            0xaf => Opcode::OP_CHECKMULTISIGVERIFY,

            // expansion
            0xb0 => Opcode::OP_NOP1,
            0xb1 => Opcode::OP_CHECKLOCKTIMEVERIFY,
            0xb2 => Opcode::OP_CHECKSEQUENCEVERIFY,
            0xb3 => Opcode::OP_NOP4,
            0xb4 => Opcode::OP_NOP5,
            0xb5 => Opcode::OP_NOP6,
            0xb6 => Opcode::OP_NOP7,
            0xb7 => Opcode::OP_NOP8,
            0xb8 => Opcode::OP_NOP9,
            0xb9 => Opcode::OP_NOP10,

            // Opcode added by BIP 342 (Tapscript)
            0xba => Opcode::OP_CHECKSIGADD,

            // Instruction from 0xbb and 0xfe are reserved for future use
            0xff => Opcode::OP_INVALIDOPCODE,
            _ => panic!("Invalid opcode"),
        }
    }
}

#[allow(non_camel_case_types, non_snake_case)]
impl From<Opcode> for u8 {
    fn from(val: Opcode) -> u8 {
        match val {
            // push value
            Opcode::OP_0 => 0x00,
            Opcode::OP_FALSE => Opcode::OP_0.into(),
            Opcode::OP_PUSHBYTES(x) => {
                if x == 0 {
                    // FIXME: check if this is true
                    panic!(
                        "The number of bytes to be pushed on the stack should be a positive value"
                    )
                } else if x >= 76 {
                    panic!("Only maximum 75 bytes can be pushed on the stack")
                } else {
                    x
                }
            }
            Opcode::OP_PUSHDATA1(_) => 0x4c,
            Opcode::OP_PUSHDATA2(_) => 0x4d,
            Opcode::OP_PUSHDATA4(_) => 0x4e,
            Opcode::OP_1NEGATE => 0x4f,
            Opcode::OP_RESERVED => 0x50,
            Opcode::OP_1 => 0x51,
            Opcode::OP_TRUE => 0x51,
            Opcode::OP_2 => 0x52,
            Opcode::OP_3 => 0x53,
            Opcode::OP_4 => 0x54,
            Opcode::OP_5 => 0x55,
            Opcode::OP_6 => 0x56,
            Opcode::OP_7 => 0x57,
            Opcode::OP_8 => 0x58,
            Opcode::OP_9 => 0x59,
            Opcode::OP_10 => 0x5a,
            Opcode::OP_11 => 0x5b,
            Opcode::OP_12 => 0x5c,
            Opcode::OP_13 => 0x5d,
            Opcode::OP_14 => 0x5e,
            Opcode::OP_15 => 0x5f,
            Opcode::OP_16 => 0x60,

            // control
            Opcode::OP_NOP => 0x61,
            Opcode::OP_VER => 0x62,
            Opcode::OP_IF => 0x63,
            Opcode::OP_NOTIF => 0x64,
            Opcode::OP_VERIF => 0x65,
            Opcode::OP_VERNOTIF => 0x66,
            Opcode::OP_ELSE => 0x67,
            Opcode::OP_ENDIF => 0x68,
            Opcode::OP_VERIFY => 0x69,
            Opcode::OP_RETURN => 0x6a,

            // stack ops
            Opcode::OP_TOALTSTACK => 0x6b,
            Opcode::OP_FROMALTSTACK => 0x6c,
            Opcode::OP_2DROP => 0x6d,
            Opcode::OP_2DUP => 0x6e,
            Opcode::OP_3DUP => 0x6f,
            Opcode::OP_2OVER => 0x70,
            Opcode::OP_2ROT => 0x71,
            Opcode::OP_2SWAP => 0x72,
            Opcode::OP_IFDUP => 0x73,
            Opcode::OP_DEPTH => 0x74,
            Opcode::OP_DROP => 0x75,
            Opcode::OP_DUP => 0x76,
            Opcode::OP_NIP => 0x77,
            Opcode::OP_OVER => 0x78,
            Opcode::OP_PICK => 0x79,
            Opcode::OP_ROLL => 0x7a,
            Opcode::OP_ROT => 0x7b,
            Opcode::OP_SWAP => 0x7c,
            Opcode::OP_TUCK => 0x7d,

            // splice ops
            Opcode::OP_CAT => 0x7e,
            Opcode::OP_SUBSTR => 0x7f,
            Opcode::OP_LEFT => 0x80,
            Opcode::OP_RIGHT => 0x81,
            Opcode::OP_SIZE => 0x82,

            // bit logic
            Opcode::OP_INVERT => 0x83,
            Opcode::OP_AND => 0x84,
            Opcode::OP_OR => 0x85,
            Opcode::OP_XOR => 0x86,
            Opcode::OP_EQUAL => 0x87,
            Opcode::OP_EQUALVERIFY => 0x88,
            Opcode::OP_RESERVED1 => 0x89,
            Opcode::OP_RESERVED2 => 0x8a,

            // numeric
            Opcode::OP_1ADD => 0x8b,
            Opcode::OP_1SUB => 0x8c,
            Opcode::OP_2MUL => 0x8d,
            Opcode::OP_2DIV => 0x8e,
            Opcode::OP_NEGATE => 0x8f,
            Opcode::OP_ABS => 0x90,
            Opcode::OP_NOT => 0x91,
            Opcode::OP_0NOTEQUAL => 0x92,

            Opcode::OP_ADD => 0x93,
            Opcode::OP_SUB => 0x94,
            Opcode::OP_MUL => 0x95,
            Opcode::OP_DIV => 0x96,
            Opcode::OP_MOD => 0x97,
            Opcode::OP_LSHIFT => 0x98,
            Opcode::OP_RSHIFT => 0x99,

            Opcode::OP_BOOLAND => 0x9a,
            Opcode::OP_BOOLOR => 0x9b,
            Opcode::OP_NUMEQUAL => 0x9c,
            Opcode::OP_NUMEQUALVERIFY => 0x9d,
            Opcode::OP_NUMNOTEQUAL => 0x9e,
            Opcode::OP_LESSTHAN => 0x9f,
            Opcode::OP_GREATERTHAN => 0xa0,
            Opcode::OP_LESSTHANOREQUAL => 0xa1,
            Opcode::OP_GREATERTHANOREQUAL => 0xa2,
            Opcode::OP_MIN => 0xa3,
            Opcode::OP_MAX => 0xa4,

            Opcode::OP_WITHIN => 0xa5,

            // crypto
            Opcode::OP_RIPEMD160 => 0xa6,
            Opcode::OP_SHA1 => 0xa7,
            Opcode::OP_SHA256 => 0xa8,
            Opcode::OP_HASH160 => 0xa9,
            Opcode::OP_HASH256 => 0xaa,
            Opcode::OP_CODESEPARATOR => 0xab,
            Opcode::OP_CHECKSIG => 0xac,
            Opcode::OP_CHECKSIGVERIFY => 0xad,
            Opcode::OP_CHECKMULTISIG => 0xae,
            Opcode::OP_CHECKMULTISIGVERIFY => 0xaf,

            // expansion
            Opcode::OP_NOP1 => 0xb0,
            Opcode::OP_CHECKLOCKTIMEVERIFY => 0xb1,
            Opcode::OP_NOP2 => 0xb1,
            Opcode::OP_CHECKSEQUENCEVERIFY => 0xb2,
            Opcode::OP_NOP3 => 0xb2,
            Opcode::OP_NOP4 => 0xb3,
            Opcode::OP_NOP5 => 0xb4,
            Opcode::OP_NOP6 => 0xb5,
            Opcode::OP_NOP7 => 0xb6,
            Opcode::OP_NOP8 => 0xb7,
            Opcode::OP_NOP9 => 0xb8,
            Opcode::OP_NOP10 => 0xb9,

            // Opcode added by BIP 342 (Tapscript)
            Opcode::OP_CHECKSIGADD => 0xba,

            Opcode::OP_INVALIDOPCODE => 0xff,
        }
    }
}

impl Opcode {
    /// Date 2024-11-16, from <https://btctools.org/opcodes-list>
    pub fn is_activated(self) -> bool {
        !matches!(
            self,
            Opcode::OP_CAT
                | Opcode::OP_SUBSTR
                | Opcode::OP_LEFT
                | Opcode::OP_RIGHT
                | Opcode::OP_INVERT
                | Opcode::OP_AND
                | Opcode::OP_OR
                | Opcode::OP_XOR
                | Opcode::OP_2MUL
                | Opcode::OP_2DIV
                | Opcode::OP_MUL
                | Opcode::OP_DIV
                | Opcode::OP_MOD
                | Opcode::OP_LSHIFT
                | Opcode::OP_RSHIFT
                | Opcode::OP_CHECKMULTISIG
                | Opcode::OP_CHECKMULTISIGVERIFY
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Instruction(Opcode),
    Data(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Script(Vec<Term>);

// FIXME: ignore if riscv32i
impl core::fmt::Display for Script {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut s = Vec::new();
        for term in &self.0 {
            match term {
                Term::Instruction(op) => s.push(format!("{}", op)),
                Term::Data(data) => {
                    let data = hex::encode(data);
                    s.push(format!("0x{}", data));
                }
            }
        }
        write!(f, "{}", s.join(" "))
    }
}

impl Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut t: Vec<u8> = vec![];
        self.0.iter().for_each(|c| match c {
            Term::Instruction(op) => match op {
                Opcode::OP_PUSHDATA1(x) => {
                    t.push(u8::from(*op));
                    t.push(*x);
                }
                Opcode::OP_PUSHDATA2([x1, x2]) => {
                    t.push(u8::from(*op));
                    t.push(*x1);
                    t.push(*x2);
                }
                Opcode::OP_PUSHDATA4([x1, x2, x3, x4]) => {
                    t.push(u8::from(*op));
                    t.push(*x1);
                    t.push(*x2);
                    t.push(*x3);
                    t.push(*x4);
                }
                _ => {
                    t.push(u8::from(*op));
                }
            },
            Term::Data(data) => {
                t.extend(data);
            }
        });
        serializer.serialize_bytes(&t)
    }
}

impl<'de> Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Script, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(deserializer)?;
        let mut terms = vec![];
        let mut i = 0;
        while i < data.len() {
            let opcode = data[i];
            if opcode == 0 {
                terms.push(Term::Instruction(Opcode::OP_0));
                i += 1;
            } else if opcode <= 75 {
                // This is a OP_PUSHBYTES. We create the OP_PUSHBYTES opcode and the
                // next {opcode} bytes are the data
                terms.push(Term::Instruction(Opcode::OP_PUSHBYTES(opcode)));
                i += 1;
                let local_data = data[i..i + opcode as usize].to_vec();
                i += opcode as usize;
                terms.push(Term::Data(local_data));
            } else if opcode == 0x4c {
                let nb_bytes = data[i + 1];
                assert!(nb_bytes >= 76);
                let local_data = data[i + 2..i + 2 + nb_bytes as usize].to_vec();
                i += 1 + 1 + nb_bytes as usize;
                terms.push(Term::Instruction(Opcode::OP_PUSHDATA1(nb_bytes)));
                terms.push(Term::Data(local_data));
            } else if opcode == 0x4d {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let mut nb_bytes: u64 = b1.into();
                nb_bytes = (nb_bytes << 8) + (b2 as u64);
                nb_bytes <<= 8;
                let local_data = data[i + 3..i + 3 + nb_bytes as usize].to_vec();
                i += 2 + 1 + nb_bytes as usize;
                terms.push(Term::Instruction(Opcode::OP_PUSHDATA2([b1, b2])));
                terms.push(Term::Data(local_data));
            } else if opcode == 0x4e {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let b3 = data[i + 3];
                let b4 = data[i + 4];
                let mut nb_bytes: u64 = b1.into();
                nb_bytes = (nb_bytes << 8) + (b2 as u64);
                nb_bytes = (nb_bytes << 8) + (b3 as u64);
                nb_bytes = (nb_bytes << 8) + (b4 as u64);
                nb_bytes <<= 8;
                let local_data = data[i + 5..i + 5 + nb_bytes as usize].to_vec();
                i += 5 + 1 + nb_bytes as usize;
                terms.push(Term::Instruction(Opcode::OP_PUSHDATA4([b1, b2, b3, b4])));
                terms.push(Term::Data(local_data));
            } else {
                terms.push(Term::Instruction(Opcode::from(opcode)));
                i += 1;
            }
        }
        Ok(Script(terms))
    }
}

impl Script {
    pub fn to_bytes(&self) -> Vec<u8> {
        let x = bincode::serialize(&self).unwrap();
        x[8..].to_vec()
    }

    pub fn of_bytes(bytes: Vec<u8>) -> Self {
        let length: u64 = bytes.len().try_into().unwrap();
        let mut bytes_with_length: Vec<u8> = length.to_le_bytes().to_vec();
        bytes_with_length.extend(bytes);
        bincode::deserialize(&bytes_with_length).unwrap()
    }

    pub fn new(instr: Vec<Term>) -> Self {
        Self(instr)
    }

    pub fn interpret(&self) -> bool {
        let mut stack = Stack::new();
        let mut exp_bytes: Option<usize> = None;
        // Execution stack for control flow (IF/NOTIF/ELSE/ENDIF)
        // Empty means executing, false means skipping this branch
        let mut vf_exec: Vec<bool> = Vec::new();

        // FIXME: remove clone
        for c in self.0.clone() {
            #[cfg(test)]
            {
                println!("Interpreting {:?}", c);
                println!("------STACK-------");
                stack.debug();
            }
            match c {
                Term::Data(v) => {
                    if exp_bytes.is_none() {
                        // A "push value" pcode should have been used just before.
                        return false;
                    } else {
                        let data = v.to_vec();
                        let exp_data_length = exp_bytes.unwrap();
                        if exp_data_length != data.len() {
                            // Wrong data length
                            return false;
                        } else {
                            stack.push(data)
                        }
                    }
                }
                Term::Instruction(opcode) => {
                    // VERIF and VERNOTIF are always invalid, even in unexecuted branches
                    // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L444
                    if matches!(opcode, Opcode::OP_VERIF | Opcode::OP_VERNOTIF) {
                        return false;
                    }

                    // Check if we're currently executing
                    let f_exec = vf_exec.iter().all(|&v| v);

                    // Skip this opcode if not executing, unless it's a control flow opcode
                    // or PUSHBYTES (which we need to parse even when skipping)
                    if !f_exec
                        && !matches!(
                            opcode,
                            Opcode::OP_IF
                                | Opcode::OP_NOTIF
                                | Opcode::OP_ELSE
                                | Opcode::OP_ENDIF
                                | Opcode::OP_PUSHBYTES(_)
                        )
                    {
                        continue;
                    }

                    match opcode {
                        // Push value opcodes
                        Opcode::OP_0 => stack.push(vec![0]),
                        Opcode::OP_FALSE => stack.push(vec![0]),
                        Opcode::OP_PUSHBYTES(n) => {
                            exp_bytes = Some(n.into());
                        }
                        Opcode::OP_1NEGATE => stack.push(vec![0x81]), // -1 in Script number format
                        Opcode::OP_1 | Opcode::OP_TRUE => stack.push(vec![1]),
                        Opcode::OP_2 => stack.push(vec![2]),
                        Opcode::OP_3 => stack.push(vec![3]),
                        Opcode::OP_4 => stack.push(vec![4]),
                        Opcode::OP_5 => stack.push(vec![5]),
                        Opcode::OP_6 => stack.push(vec![6]),
                        Opcode::OP_7 => stack.push(vec![7]),
                        Opcode::OP_8 => stack.push(vec![8]),
                        Opcode::OP_9 => stack.push(vec![9]),
                        Opcode::OP_10 => stack.push(vec![10]),
                        Opcode::OP_11 => stack.push(vec![11]),
                        Opcode::OP_12 => stack.push(vec![12]),
                        Opcode::OP_13 => stack.push(vec![13]),
                        Opcode::OP_14 => stack.push(vec![14]),
                        Opcode::OP_15 => stack.push(vec![15]),
                        Opcode::OP_16 => stack.push(vec![16]),

                        // Control flow opcodes
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L451
                        Opcode::OP_IF | Opcode::OP_NOTIF => {
                            let mut f_value = false;

                            // Check if we're currently executing
                            if vf_exec.iter().all(|&v| v) {
                                // We're executing, so evaluate the condition
                                if !stack.has(1) {
                                    return false;
                                }
                                let vch = stack.pop_unwrap();
                                // Value is true if not empty and not all zeros
                                f_value = !vch.is_empty() && vch.iter().any(|&x| x != 0);

                                // NOTIF inverts the condition
                                if opcode == Opcode::OP_NOTIF {
                                    f_value = !f_value;
                                }
                            }
                            // If we're skipping, just push false to maintain nesting
                            vf_exec.push(f_value);
                        }

                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L464
                        Opcode::OP_ELSE => {
                            if vf_exec.is_empty() {
                                return false; // ELSE without IF
                            }
                            let last_idx = vf_exec.len() - 1;
                            vf_exec[last_idx] = !vf_exec[last_idx];
                        }

                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L467
                        Opcode::OP_ENDIF => {
                            if vf_exec.is_empty() {
                                return false; // ENDIF without IF
                            }
                            vf_exec.pop();
                        }

                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L499
                        Opcode::OP_RETURN => {
                            return false;
                        }

                        // Stack manipulation
                        Opcode::OP_DROP => {
                            if !stack.has(1) {
                                return false;
                            }
                            stack.pop_unwrap();
                        }
                        Opcode::OP_DUP => {
                            if !stack.has(1) {
                                return false;
                            }
                            let hd = stack.pop_unwrap();
                            stack.push(hd.clone());
                            stack.push(hd);
                        }
                        Opcode::OP_NIP => {
                            if !stack.has(2) {
                                return false;
                            }
                            let top = stack.pop_unwrap();
                            stack.pop_unwrap(); // Remove second item
                            stack.push(top);
                        }
                        Opcode::OP_OVER => {
                            if !stack.has(2) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            stack.push(b.clone());
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_SWAP => {
                            if !stack.has(2) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_TUCK => {
                            if !stack.has(2) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            stack.push(a.clone());
                            stack.push(b);
                            stack.push(a);
                        }
                        Opcode::OP_2DROP => {
                            if !stack.has(2) {
                                return false;
                            }
                            stack.pop_unwrap();
                            stack.pop_unwrap();
                        }
                        Opcode::OP_2DUP => {
                            if !stack.has(2) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            stack.push(b.clone());
                            stack.push(a.clone());
                            stack.push(b);
                            stack.push(a);
                        }
                        Opcode::OP_3DUP => {
                            if !stack.has(3) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let c = stack.pop_unwrap();
                            stack.push(c.clone());
                            stack.push(b.clone());
                            stack.push(a.clone());
                            stack.push(c);
                            stack.push(b);
                            stack.push(a);
                        }
                        Opcode::OP_2OVER => {
                            if !stack.has(4) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let c = stack.pop_unwrap();
                            let d = stack.pop_unwrap();
                            stack.push(d.clone());
                            stack.push(c.clone());
                            stack.push(b);
                            stack.push(a);
                            stack.push(d);
                            stack.push(c);
                        }
                        Opcode::OP_2ROT => {
                            if !stack.has(6) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let c = stack.pop_unwrap();
                            let d = stack.pop_unwrap();
                            let e = stack.pop_unwrap();
                            let f = stack.pop_unwrap();
                            stack.push(d);
                            stack.push(c);
                            stack.push(b);
                            stack.push(a);
                            stack.push(f);
                            stack.push(e);
                        }
                        Opcode::OP_2SWAP => {
                            if !stack.has(4) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let c = stack.pop_unwrap();
                            let d = stack.pop_unwrap();
                            stack.push(b);
                            stack.push(a);
                            stack.push(d);
                            stack.push(c);
                        }
                        Opcode::OP_ROT => {
                            if !stack.has(3) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let c = stack.pop_unwrap();
                            stack.push(b);
                            stack.push(a);
                            stack.push(c);
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L470
                        Opcode::OP_TOALTSTACK => {
                            if !stack.has(1) {
                                return false;
                            }
                            stack.to_altstack();
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L475
                        Opcode::OP_FROMALTSTACK => {
                            if !stack.has_alt(1) {
                                return false;
                            }
                            stack.from_altstack();
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L560
                        Opcode::OP_IFDUP => {
                            if !stack.has(1) {
                                return false;
                            }
                            let top = &stack.main[stack.len() - 1];
                            // Duplicate if not zero
                            if !top.is_empty() && top.iter().any(|&x| x != 0) {
                                stack.push(top.clone());
                            }
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L567
                        Opcode::OP_DEPTH => {
                            let depth = stack.len() as u32;
                            stack.push(depth.to_le_bytes().to_vec());
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L580
                        Opcode::OP_PICK => {
                            if !stack.has(1) {
                                return false;
                            }
                            let n_bytes = stack.pop_unwrap();
                            let n = if n_bytes.is_empty() {
                                0
                            } else {
                                n_bytes[0] as usize
                            };
                            if !stack.has(n + 1) {
                                return false;
                            }
                            let idx = stack.len() - 1 - n;
                            let val = stack.main[idx].clone();
                            stack.push(val);
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L589
                        Opcode::OP_ROLL => {
                            if !stack.has(1) {
                                return false;
                            }
                            let n_bytes = stack.pop_unwrap();
                            let n = if n_bytes.is_empty() {
                                0
                            } else {
                                n_bytes[0] as usize
                            };
                            if !stack.has(n + 1) {
                                return false;
                            }
                            let idx = stack.len() - 1 - n;
                            let val = stack.main.remove(idx);
                            stack.push(val);
                        }
                        Opcode::OP_SIZE => {
                            if !stack.has(1) {
                                return false;
                            }
                            let top = stack.pop_unwrap();
                            let size = top.len() as u32;
                            stack.push(top);
                            stack.push(size.to_le_bytes().to_vec());
                        }

                        // Bit logic
                        Opcode::OP_EQUAL => {
                            if !stack.has(2) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let b = stack.pop_unwrap();
                            let is_equal =
                                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y);
                            stack.push(vec![is_equal as u8]);
                        }
                        Opcode::OP_EQUALVERIFY => {
                            if !stack.has(2) {
                                return false;
                            }
                            let lhs = stack.pop_unwrap();
                            let rhs = stack.pop_unwrap();
                            let is_equal = lhs.len() == rhs.len()
                                && lhs.iter().zip(rhs.iter()).all(|(x, y)| x == y);
                            stack.push(vec![is_equal as u8]);
                            let res = stack.pop_unwrap();
                            let is_true = res.len() == 1 && res[0] == 1;
                            if !is_true {
                                return false;
                            }
                        }

                        // Crypto
                        Opcode::OP_RIPEMD160 => {
                            if !stack.has(1) {
                                return false;
                            }
                            let data = stack.pop_unwrap();
                            let mut hasher = Ripemd160::new();
                            hasher.update(&data);
                            let result = hasher.finalize();
                            stack.push(result.to_vec());
                        }
                        Opcode::OP_SHA256 => {
                            if !stack.has(1) {
                                return false;
                            }
                            let data = stack.pop_unwrap();
                            let result = Sha256::digest(&data);
                            stack.push(result.to_vec());
                        }
                        Opcode::OP_HASH160 => {
                            if !stack.has(1) {
                                return false;
                            }
                            let hd = stack.pop_unwrap();
                            let res = Sha256::digest(&hd);
                            let mut hasher = Ripemd160::new();
                            hasher.update(res);
                            let result = hasher.finalize();
                            stack.push(result.to_vec());
                        }
                        Opcode::OP_HASH256 => {
                            if !stack.has(1) {
                                return false;
                            }
                            let data = stack.pop_unwrap();
                            let res1 = Sha256::digest(&data);
                            let res2 = Sha256::digest(&res1);
                            stack.push(res2.to_vec());
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1166
                        Opcode::OP_SHA1 => {
                            if !stack.has(1) {
                                return false;
                            }
                            let data = stack.pop_unwrap();
                            let result = Sha1::digest(&data);
                            stack.push(result.to_vec());
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1178
                        Opcode::OP_CODESEPARATOR => {
                            // In Bitcoin, this opcode marks a boundary for signature checking
                            // It affects which parts of the script are hashed for signature verification
                            // For now, we implement it as a no-op since signature verification is TODO
                            // TODO: Track the position for proper CHECKSIG implementation
                        }
                        Opcode::OP_CHECKSIG => {
                            if !stack.has(2) {
                                return false;
                            }
                            let _pubkey = stack.pop_unwrap();
                            let _signature = stack.pop_unwrap();
                            // TODO: Implement actual signature verification
                            // For now, push true (1) as a placeholder
                            stack.push(vec![1]);
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1254
                        Opcode::OP_CHECKSIGVERIFY => {
                            if !stack.has(2) {
                                return false;
                            }
                            let _pubkey = stack.pop_unwrap();
                            let _signature = stack.pop_unwrap();
                            // TODO: Implement actual signature verification
                            // For now, assume success as placeholder
                            // In real implementation, this should:
                            // 1. Perform CHECKSIG
                            // 2. Then VERIFY (fail if false)
                            // For now, we just succeed
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1258
                        Opcode::OP_CHECKMULTISIG => {
                            // Pop the number of public keys
                            if !stack.has(1) {
                                return false;
                            }
                            let n_pubkeys_bytes = stack.pop_unwrap();
                            let n_pubkeys = if n_pubkeys_bytes.is_empty() {
                                0
                            } else {
                                n_pubkeys_bytes[0] as usize
                            };

                            if n_pubkeys > 20 {
                                return false; // Limit of 20 public keys
                            }

                            // Pop the public keys
                            if !stack.has(n_pubkeys) {
                                return false;
                            }
                            for _ in 0..n_pubkeys {
                                stack.pop_unwrap();
                            }

                            // Pop the number of signatures
                            if !stack.has(1) {
                                return false;
                            }
                            let n_sigs_bytes = stack.pop_unwrap();
                            let n_sigs = if n_sigs_bytes.is_empty() {
                                0
                            } else {
                                n_sigs_bytes[0] as usize
                            };

                            if n_sigs > n_pubkeys {
                                return false;
                            }

                            // Pop the signatures
                            if !stack.has(n_sigs) {
                                return false;
                            }
                            for _ in 0..n_sigs {
                                stack.pop_unwrap();
                            }

                            // Pop the extra dummy value (Bitcoin Core bug workaround)
                            if !stack.has(1) {
                                return false;
                            }
                            stack.pop_unwrap();

                            // TODO: Implement actual signature verification
                            // For now, push true (1) as a placeholder
                            stack.push(vec![1]);
                        }
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1350
                        Opcode::OP_CHECKMULTISIGVERIFY => {
                            // This is CHECKMULTISIG followed by VERIFY
                            // For now, we'll implement it similar to CHECKMULTISIG

                            // Pop the number of public keys
                            if !stack.has(1) {
                                return false;
                            }
                            let n_pubkeys_bytes = stack.pop_unwrap();
                            let n_pubkeys = if n_pubkeys_bytes.is_empty() {
                                0
                            } else {
                                n_pubkeys_bytes[0] as usize
                            };

                            if n_pubkeys > 20 {
                                return false;
                            }

                            // Pop the public keys
                            if !stack.has(n_pubkeys) {
                                return false;
                            }
                            for _ in 0..n_pubkeys {
                                stack.pop_unwrap();
                            }

                            // Pop the number of signatures
                            if !stack.has(1) {
                                return false;
                            }
                            let n_sigs_bytes = stack.pop_unwrap();
                            let n_sigs = if n_sigs_bytes.is_empty() {
                                0
                            } else {
                                n_sigs_bytes[0] as usize
                            };

                            if n_sigs > n_pubkeys {
                                return false;
                            }

                            // Pop the signatures
                            if !stack.has(n_sigs) {
                                return false;
                            }
                            for _ in 0..n_sigs {
                                stack.pop_unwrap();
                            }

                            // Pop the extra dummy value
                            if !stack.has(1) {
                                return false;
                            }
                            stack.pop_unwrap();

                            // TODO: Implement actual signature verification
                            // For now, assume success (don't push anything, just succeed)
                        }
                        // Reference: BIP 342 (Tapscript)
                        Opcode::OP_CHECKSIGADD => {
                            // This is a Tapscript opcode (BIP 342)
                            // It's more complex and requires Schnorr signature support
                            if !stack.has(3) {
                                return false;
                            }
                            let _pubkey = stack.pop_unwrap();
                            let _n = stack.pop_unwrap();
                            let _signature = stack.pop_unwrap();

                            // TODO: Implement Tapscript CHECKSIGADD
                            // For now, push 1 as placeholder (successful signature)
                            stack.push(vec![1]);
                        }

                        // Numeric operations
                        Opcode::OP_1ADD => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            if a.is_empty() {
                                stack.push(vec![1]);
                            } else {
                                let val = a[0] as i32 + 1;
                                stack.push(vec![val as u8]);
                            }
                        }
                        Opcode::OP_1SUB => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            if a.is_empty() {
                                stack.push(vec![0x81]); // -1
                            } else {
                                let val = a[0] as i32 - 1;
                                if val < 0 {
                                    stack.push(vec![0x81]); // -1 in Script format
                                } else {
                                    stack.push(vec![val as u8]);
                                }
                            }
                        }
                        Opcode::OP_NEGATE => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            if !a.is_empty() {
                                if a[0] == 0x81 {
                                    // -1 becomes 1
                                    stack.push(vec![1]);
                                } else if a[0] == 0 {
                                    stack.push(vec![0]);
                                } else {
                                    // Positive becomes negative (add 0x80 flag)
                                    stack.push(vec![a[0] | 0x80]);
                                }
                            } else {
                                stack.push(vec![0]);
                            }
                        }
                        Opcode::OP_ABS => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            if !a.is_empty() {
                                // Remove sign bit if present
                                stack.push(vec![a[0] & 0x7F]);
                            } else {
                                stack.push(vec![0]);
                            }
                        }
                        Opcode::OP_NOT => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let is_zero = a.is_empty() || a.iter().all(|&x| x == 0);
                            stack.push(vec![is_zero as u8]);
                        }
                        Opcode::OP_0NOTEQUAL => {
                            if !stack.has(1) {
                                return false;
                            }
                            let a = stack.pop_unwrap();
                            let is_nonzero = !a.is_empty() && a.iter().any(|&x| x != 0);
                            stack.push(vec![is_nonzero as u8]);
                        }
                        Opcode::OP_ADD => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            let result = a_val + b_val;
                            if result < 0 {
                                stack.push(vec![(-result) as u8 | 0x80]);
                            } else {
                                stack.push(vec![result as u8]);
                            }
                        }
                        Opcode::OP_SUB => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            let result = a_val - b_val;
                            if result < 0 {
                                stack.push(vec![(-result) as u8 | 0x80]);
                            } else {
                                stack.push(vec![result as u8]);
                            }
                        }
                        Opcode::OP_BOOLAND => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_true = !a.is_empty() && a.iter().any(|&x| x != 0);
                            let b_true = !b.is_empty() && b.iter().any(|&x| x != 0);
                            stack.push(vec![(a_true && b_true) as u8]);
                        }
                        Opcode::OP_BOOLOR => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_true = !a.is_empty() && a.iter().any(|&x| x != 0);
                            let b_true = !b.is_empty() && b.iter().any(|&x| x != 0);
                            stack.push(vec![(a_true || b_true) as u8]);
                        }
                        Opcode::OP_NUMEQUAL => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let is_equal =
                                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y);
                            stack.push(vec![is_equal as u8]);
                        }
                        Opcode::OP_NUMEQUALVERIFY => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let is_equal =
                                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y);
                            if !is_equal {
                                return false;
                            }
                        }
                        Opcode::OP_NUMNOTEQUAL => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let is_not_equal =
                                a.len() != b.len() || !a.iter().zip(b.iter()).all(|(x, y)| x == y);
                            stack.push(vec![is_not_equal as u8]);
                        }
                        Opcode::OP_LESSTHAN => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            stack.push(vec![(a_val < b_val) as u8]);
                        }
                        Opcode::OP_GREATERTHAN => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            stack.push(vec![(a_val > b_val) as u8]);
                        }
                        Opcode::OP_LESSTHANOREQUAL => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            stack.push(vec![(a_val <= b_val) as u8]);
                        }
                        Opcode::OP_GREATERTHANOREQUAL => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            stack.push(vec![(a_val >= b_val) as u8]);
                        }
                        Opcode::OP_MIN => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            if a_val < b_val {
                                stack.push(a);
                            } else {
                                stack.push(b);
                            }
                        }
                        Opcode::OP_MAX => {
                            if !stack.has(2) {
                                return false;
                            }
                            let b = stack.pop_unwrap();
                            let a = stack.pop_unwrap();
                            let a_val = if a.is_empty() { 0 } else { a[0] as i32 };
                            let b_val = if b.is_empty() { 0 } else { b[0] as i32 };
                            if a_val > b_val {
                                stack.push(a);
                            } else {
                                stack.push(b);
                            }
                        }
                        Opcode::OP_WITHIN => {
                            if !stack.has(3) {
                                return false;
                            }
                            let max = stack.pop_unwrap();
                            let min = stack.pop_unwrap();
                            let x = stack.pop_unwrap();
                            let x_val = if x.is_empty() { 0 } else { x[0] as i32 };
                            let min_val = if min.is_empty() { 0 } else { min[0] as i32 };
                            let max_val = if max.is_empty() { 0 } else { max[0] as i32 };
                            let within = x_val >= min_val && x_val < max_val;
                            stack.push(vec![within as u8]);
                        }

                        // Control flow
                        Opcode::OP_NOP => {
                            // No operation
                        }
                        Opcode::OP_VERIFY => {
                            if !stack.has(1) {
                                return false;
                            }
                            let val = stack.pop_unwrap();
                            let is_true = !val.is_empty() && val != vec![0];
                            if !is_true {
                                return false;
                            }
                        }

                        // Disabled/Reserved opcodes - always fail when executed
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L360
                        Opcode::OP_RESERVED
                        | Opcode::OP_VER
                        | Opcode::OP_RESERVED1
                        | Opcode::OP_RESERVED2 => {
                            return false;
                        }

                        // Disabled opcodes - string operations
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L365
                        Opcode::OP_CAT | Opcode::OP_SUBSTR | Opcode::OP_LEFT | Opcode::OP_RIGHT => {
                            return false;
                        }

                        // Disabled opcodes - bitwise operations
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L369
                        Opcode::OP_INVERT | Opcode::OP_AND | Opcode::OP_OR | Opcode::OP_XOR => {
                            return false;
                        }

                        // Disabled opcodes - numeric operations
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L373
                        Opcode::OP_2MUL
                        | Opcode::OP_2DIV
                        | Opcode::OP_MUL
                        | Opcode::OP_DIV
                        | Opcode::OP_MOD => {
                            return false;
                        }

                        // Disabled opcodes - bit shift operations
                        // Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L377
                        Opcode::OP_LSHIFT | Opcode::OP_RSHIFT => {
                            return false;
                        }

                        _ => unimplemented!("The opcode {opcode} is not implemented"),
                    }
                }
            }
        }
        #[cfg(test)]
        println!("Stack at the end: {:?}", stack.main);

        // Check for unbalanced IF/ENDIF
        if !vf_exec.is_empty() {
            return false;
        }

        // Script succeeds if stack is not empty and top element is true
        if stack.main.is_empty() {
            return false;
        }
        let top = &stack.main[stack.main.len() - 1];
        // Element is true if it's not empty and not all zeros
        !top.is_empty() && top.iter().any(|&x| x != 0)
    }
}
