//! This module provides an implementation of Bitcoin script

use core::convert::From;
use core::convert::Into;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

pub struct Stack(Vec<Vec<u8>>);

impl Stack {
    pub fn new() -> Self {
        Self(vec![])
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
    OP_0,
    OP_FALSE,
    OP_PUSHBYTES(u8),
    OP_PUSHDATA1(u8),
    OP_PUSHDATA2([u8; 2]),
    OP_PUSHDATA4([u8; 4]),
    OP_1NEGATE,
    OP_RESERVED,
    OP_1,
    OP_TRUE,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    // control
    OP_NOP,
    OP_VER,
    OP_IF,
    OP_NOTIF,
    OP_VERIF,
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,
    OP_RETURN,

    // stack ops
    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    // splice ops
    OP_CAT,
    OP_SUBSTR,
    OP_LEFT,
    OP_RIGHT,
    OP_SIZE,

    // bit logic
    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_RESERVED1,
    OP_RESERVED2,

    // numeric
    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,

    // crypto
    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,
    OP_HASH256,
    OP_CODESEPARATOR,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,

    // expansion
    OP_NOP1,
    OP_CHECKLOCKTIMEVERIFY,
    OP_NOP2,
    OP_CHECKSEQUENCEVERIFY,
    OP_NOP3,
    OP_NOP4,
    OP_NOP5,
    OP_NOP6,
    OP_NOP7,
    OP_NOP8,
    OP_NOP9,
    OP_NOP10,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD,

    OP_INVALIDOPCODE,
}

// FIXME: ignore if riscv32i
impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
    /// Date 2024-11-16, from https://btctools.org/opcodes-list
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
impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
            } else if opcode == 76 {
                let nb_bytes = data[i + 1];
                assert!(nb_bytes >= 76);
                let local_data = data[i + 2..i + 2 + nb_bytes as usize].to_vec();
                i += 1 + 1 + nb_bytes as usize;
                terms.push(Term::Instruction(Opcode::OP_PUSHDATA1(nb_bytes)));
                terms.push(Term::Data(local_data));
            } else if opcode == 77 {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let nb_bytes = b1 << 16 + b2;
                let local_data = data[i + 3..i + 3 + nb_bytes as usize].to_vec();
                i += 2 + 1 + nb_bytes as usize;
                terms.push(Term::Instruction(Opcode::OP_PUSHDATA2([b1, b2])));
                terms.push(Term::Data(local_data));
            } else if opcode == 78 {
                unimplemented!("TODO")
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

    pub fn new(instr: Vec<Term>) -> Self {
        Self(instr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{deserialize, serialize};
    use hex;

    // Examples from https://learnmeabitcoin.com/technical/transaction/input/scriptsig/
    #[test]
    pub fn test_to_bytes() {
        // P2PKH
        {
            let data = "3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401";
            let hex_data: Vec<u8> = hex::decode(data).unwrap();
            let data2 = "03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31";
            let hex_data2: Vec<u8> = hex::decode(data2).unwrap();
            let script = Script(vec![
                Term::Instruction(Opcode::OP_PUSHBYTES(72)),
                Term::Data(hex_data),
                Term::Instruction(Opcode::OP_PUSHBYTES(33)),
                Term::Data(hex_data2),
            ]);

            let exp_output = "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31";
            let exp_output = hex::decode(exp_output).unwrap();
            assert_eq!(exp_output, script.to_bytes());
        }
        // P2PK
        {
            let data = "30440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01";
            let data: Vec<u8> = hex::decode(data).unwrap();
            let script = Script(vec![
                Term::Instruction(Opcode::OP_PUSHBYTES(71)),
                Term::Data(data),
            ]);
            let exp_output = "4730440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01";
            let exp_output = hex::decode(exp_output).unwrap();
            assert_eq!(exp_output, script.to_bytes());
        }
        // P2MS
        {
            let data = "304502204aa764d2b30f572cc4ef17c8ed8536c46f595a08ba41a611b14f32c60282c150022100ede45011be565dc225cc9be292638cf7270b129934fe8758634716b8f7a34c0701";
            let data = hex::decode(data).unwrap();
            let script = Script(vec![
                Term::Instruction(Opcode::OP_0),
                Term::Instruction(Opcode::OP_PUSHBYTES(72)),
                Term::Data(data),
            ]);
            let exp_output = "0048304502204aa764d2b30f572cc4ef17c8ed8536c46f595a08ba41a611b14f32c60282c150022100ede45011be565dc225cc9be292638cf7270b129934fe8758634716b8f7a34c0701";
            let exp_output = hex::decode(exp_output).unwrap();
            assert_eq!(exp_output, script.to_bytes());
        }
        // P2SH
        {
            let data = "3044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401";
            let data = hex::decode(data).unwrap();

            let data2 = "5121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae";
            let data2 = hex::decode(data2).unwrap();
            let script = Script(vec![
                Term::Instruction(Opcode::OP_0),
                Term::Instruction(Opcode::OP_PUSHBYTES(71)),
                Term::Data(data),
                Term::Instruction(Opcode::OP_PUSHBYTES(71)),
                Term::Data(data2),
            ]);
            let exp_output = "00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae";
            let exp_output = hex::decode(exp_output).unwrap();
            assert_eq!(exp_output, script.to_bytes());
        }
        // Genesis bloc - coinbase
        {
            let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
            let data = hex::decode(data).unwrap();
            let script = Script(vec![
                Term::Instruction(Opcode::OP_PUSHBYTES(4)),
                Term::Data(hex::decode("ffff001d").unwrap()),
                Term::Instruction(Opcode::OP_PUSHBYTES(1)),
                Term::Data(hex::decode("04").unwrap()),
                Term::Instruction(Opcode::OP_PUSHBYTES(69)),
                Term::Data(data),
            ]);
            let exp_output = "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
            let exp_output = hex::decode(exp_output).unwrap();
            assert_eq!(exp_output, script.to_bytes());
        }
    }

    #[test]
    pub fn test_decode_pushdata1() {
        let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let data = hex::decode(data).unwrap();
        let script = Script(vec![
            Term::Instruction(Opcode::OP_PUSHDATA1(0x4c)),
            Term::Data(data),
        ]);
        let exp_output = "4c4caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }

    #[test]
    pub fn test_decode_pushdata2() {
        let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let data = hex::decode(data).unwrap();
        let script = Script(vec![
            Term::Instruction(Opcode::OP_PUSHDATA2([0x00, 0x01])),
            Term::Data(data),
        ]);
        let exp_output = "4d0001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }

    #[test]
    pub fn test_serialize_and_deserialize() {
        let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
        let data = hex::decode(data).unwrap();
        let script = Script(vec![
            Term::Instruction(Opcode::OP_PUSHBYTES(4)),
            Term::Data(hex::decode("ffff001d").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(1)),
            Term::Data(hex::decode("04").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(69)),
            Term::Data(data),
        ]);
        // Checking serialize/deserialize works together
        let res: Vec<u8> = serialize(&script).unwrap();
        let script2: Script = deserialize(&res).unwrap();
        assert_eq!(script, script2);
    }

    // FIXME: ignore if riscv32i
    #[test]
    pub fn test_display_asm() {
        let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
        let data = hex::decode(data).unwrap();
        let script = Script(vec![
            Term::Instruction(Opcode::OP_PUSHBYTES(4)),
            Term::Data(hex::decode("ffff001d").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(1)),
            Term::Data(hex::decode("04").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(69)),
            Term::Data(data),
        ]);

        assert_eq!(
            script.to_string(),
            "OP_PUSHBYTES4 0xffff001d OP_PUSHBYTES1 0x04 OP_PUSHBYTES69 0x5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
        );
    }
}
