use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L438

#[test]
pub fn test_op_1negate() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1NEGATE),
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(vec![0x81]), // -1 in Script number format
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}
