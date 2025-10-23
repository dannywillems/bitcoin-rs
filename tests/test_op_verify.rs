use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L413

#[test]
pub fn test_op_verify() {
    // OP_VERIFY pops and verifies, so we need something left on stack
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_VERIFY),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_verify_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_VERIFY),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_verify_fails_empty_stack() {
    // OP_VERIFY should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_VERIFY)]);
    assert!(!script.interpret());
}
