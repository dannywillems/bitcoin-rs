use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L817

#[test]
pub fn test_op_min() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_MIN),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_min_fails_insufficient_stack() {
    // OP_MIN should fail when stack has less than 2 elements
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_MIN),
    ]);
    assert!(!script.interpret());
}
