use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L671

#[test]
pub fn test_op_1add() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_1ADD),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_1add_fails_empty_stack() {
    // OP_1ADD should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_1ADD)]);
    assert!(!script.interpret());
}
