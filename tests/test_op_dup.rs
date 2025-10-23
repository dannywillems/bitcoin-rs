use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L485

#[test]
pub fn test_op_dup() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_DUP),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_dup_fails_empty_stack() {
    // OP_DUP should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_DUP)]);
    assert!(!script.interpret());
}
