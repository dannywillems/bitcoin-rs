use bitcoin_rs::script::{Opcode, Script, Term};

// Note: These tests use placeholder implementations
// Real signature verification is TODO

#[test]
pub fn test_op_checksig_basic() {
    // CHECKSIG should pop signature and pubkey, push result
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(vec![0xaa]), // Dummy signature
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(vec![0xbb]), // Dummy pubkey
        Term::Instruction(Opcode::OP_CHECKSIG),
        // Currently pushes 1 (true) as placeholder
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_checksig_fails_insufficient_stack() {
    // CHECKSIG needs 2 items on stack
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_CHECKSIG),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_checksigverify_basic() {
    // CHECKSIGVERIFY should verify signature (placeholder: always succeeds)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(vec![0xaa]), // Dummy signature
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(vec![0xbb]), // Dummy pubkey
        Term::Instruction(Opcode::OP_CHECKSIGVERIFY),
        Term::Instruction(Opcode::OP_1), // Script succeeds
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_checksigverify_fails_insufficient_stack() {
    // CHECKSIGVERIFY needs 2 items on stack
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_CHECKSIGVERIFY),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_codeseparator() {
    // CODESEPARATOR is a no-op in our current implementation
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_CODESEPARATOR),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}
