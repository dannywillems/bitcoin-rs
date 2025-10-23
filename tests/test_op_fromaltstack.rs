use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L475

#[test]
pub fn test_op_fromaltstack() {
    // Move value to altstack and back
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_TOALTSTACK),
        Term::Instruction(Opcode::OP_FROMALTSTACK),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_fromaltstack_multiple() {
    // Test multiple items on altstack
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_TOALTSTACK),
        Term::Instruction(Opcode::OP_TOALTSTACK),
        Term::Instruction(Opcode::OP_FROMALTSTACK), // Gets 1
        Term::Instruction(Opcode::OP_FROMALTSTACK), // Gets 2
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_fromaltstack_fails_empty_altstack() {
    // OP_FROMALTSTACK should fail when altstack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_FROMALTSTACK)]);
    assert!(!script.interpret());
}
