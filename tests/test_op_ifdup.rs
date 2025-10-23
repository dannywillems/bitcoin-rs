use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L560

#[test]
pub fn test_op_ifdup_duplicates_non_zero() {
    // IFDUP should duplicate if value is non-zero
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IFDUP),
        // Now should have two 1s on stack
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
        Term::Instruction(Opcode::OP_VERIFY),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_ifdup_does_not_duplicate_zero() {
    // IFDUP should not duplicate if value is zero
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_IFDUP),
        // Should still have only one 0 on stack
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_ifdup_fails_empty_stack() {
    // IFDUP should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_IFDUP)]);
    assert!(!script.interpret());
}
