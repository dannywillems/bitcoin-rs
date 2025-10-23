use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L765

#[test]
pub fn test_op_boolor() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_BOOLOR),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_boolor_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_BOOLOR),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_boolor_fails_insufficient_stack() {
    // OP_BOOLOR should fail when stack has less than 2 elements
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_BOOLOR),
    ]);
    assert!(!script.interpret());
}
