use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L757

#[test]
pub fn test_op_booland() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_BOOLAND),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_booland_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_BOOLAND),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_booland_fails_insufficient_stack() {
    // OP_BOOLAND should fail when stack has less than 2 elements
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_BOOLAND),
    ]);
    assert!(!script.interpret());
}
