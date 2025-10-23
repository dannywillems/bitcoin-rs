use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L933

#[test]
pub fn test_op_hash256() {
    // Test double SHA256
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(5)),
        Term::Data(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]), // "hello"
        Term::Instruction(Opcode::OP_HASH256),
        // Result should be 32 bytes
        Term::Instruction(Opcode::OP_SIZE),
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(vec![32, 0, 0, 0]),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_hash256_fails_empty_stack() {
    // OP_HASH256 should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_HASH256)]);
    assert!(!script.interpret());
}
