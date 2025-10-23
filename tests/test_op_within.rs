use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L833

#[test]
pub fn test_op_within() {
    // Test if 3 is within [2, 5)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_3), // x
        Term::Instruction(Opcode::OP_2), // min
        Term::Instruction(Opcode::OP_5), // max
        Term::Instruction(Opcode::OP_WITHIN),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_within_fails() {
    // Test if 5 is within [2, 5) - should fail (max is exclusive)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5), // x
        Term::Instruction(Opcode::OP_2), // min
        Term::Instruction(Opcode::OP_5), // max
        Term::Instruction(Opcode::OP_WITHIN),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_within_fails_insufficient_stack() {
    // OP_WITHIN should fail when stack has less than 3 elements
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_WITHIN),
    ]);
    assert!(!script.interpret());
}
