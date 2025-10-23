use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L470

#[test]
pub fn test_op_toaltstack() {
    // Push values, move one to altstack, then bring it back
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_TOALTSTACK), // Move 2 to altstack
        Term::Instruction(Opcode::OP_FROMALTSTACK), // Bring 2 back
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_EQUAL), // Check top is 2
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_toaltstack_preserves_order() {
    // Test that altstack preserves order (LIFO)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_TOALTSTACK), // Move 3 to altstack
        Term::Instruction(Opcode::OP_TOALTSTACK), // Move 2 to altstack
        Term::Instruction(Opcode::OP_FROMALTSTACK), // Brings back 2
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_toaltstack_fails_empty_stack() {
    // OP_TOALTSTACK should fail when main stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_TOALTSTACK)]);
    assert!(!script.interpret());
}
