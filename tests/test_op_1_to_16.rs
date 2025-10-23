use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L442

#[test]
pub fn test_op_1_to_16() {
    // Test OP_1 through OP_16
    for i in 1..=16 {
        let script = Script::new(vec![
            Term::Instruction(match i {
                1 => Opcode::OP_1,
                2 => Opcode::OP_2,
                3 => Opcode::OP_3,
                4 => Opcode::OP_4,
                5 => Opcode::OP_5,
                6 => Opcode::OP_6,
                7 => Opcode::OP_7,
                8 => Opcode::OP_8,
                9 => Opcode::OP_9,
                10 => Opcode::OP_10,
                11 => Opcode::OP_11,
                12 => Opcode::OP_12,
                13 => Opcode::OP_13,
                14 => Opcode::OP_14,
                15 => Opcode::OP_15,
                16 => Opcode::OP_16,
                _ => unreachable!(),
            }),
            Term::Instruction(Opcode::OP_PUSHBYTES(1)),
            Term::Data(vec![i as u8]),
            Term::Instruction(Opcode::OP_EQUAL),
        ]);
        assert!(script.interpret());
    }
}
