use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L636

#[test]
pub fn test_op_size() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(3)),
        Term::Data(vec![0xAA, 0xBB, 0xCC]),
        Term::Instruction(Opcode::OP_SIZE),
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(vec![3, 0, 0, 0]), // Size 3 in little-endian
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_size_fails_empty_stack() {
    // OP_SIZE should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_SIZE)]);
    assert!(!script.interpret());
}
