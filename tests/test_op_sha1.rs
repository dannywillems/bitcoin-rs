use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L1166

#[test]
pub fn test_op_sha1_basic() {
    // SHA1 should hash the top stack item
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(5)),
        Term::Data(b"hello".to_vec()),
        Term::Instruction(Opcode::OP_SHA1),
        // Expected: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d (SHA1 of "hello")
        Term::Instruction(Opcode::OP_PUSHBYTES(20)),
        Term::Data(
            hex::decode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
                .unwrap()
                .to_vec(),
        ),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_sha1_empty() {
    // SHA1 of empty string
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(0)),
        Term::Data(vec![]),
        Term::Instruction(Opcode::OP_SHA1),
        // Expected: da39a3ee5e6b4b0d3255bfef95601890afd80709 (SHA1 of "")
        Term::Instruction(Opcode::OP_PUSHBYTES(20)),
        Term::Data(
            hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709")
                .unwrap()
                .to_vec(),
        ),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_sha1_fails_empty_stack() {
    // SHA1 should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_SHA1)]);
    assert!(!script.interpret());
}
