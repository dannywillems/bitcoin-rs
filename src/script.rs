//! This module provides an implementation of Bitcoin script

use core::convert::From;
use core::convert::Into;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // push value
    OP_0,
    OP_FALSE,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
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

#[allow(non_camel_case_types, non_snake_case)]
impl From<Opcode> for u8 {
    fn from(val: Opcode) -> u8 {
        match val {
            // push value
            Opcode::OP_0 => 0x00,
            Opcode::OP_FALSE => Opcode::OP_0.into(),
            Opcode::OP_PUSHDATA1 => 0x4c,
            Opcode::OP_PUSHDATA2 => 0x4d,
            Opcode::OP_PUSHDATA4 => 0x4e,
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
