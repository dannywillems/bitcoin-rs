use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L711

#[test]
pub fn test_op_0notequal() {
    // Test 0NOTEQUAL on non-zero returns true
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_0NOTEQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_0notequal_fails() {
    // Test 0NOTEQUAL on zero returns false
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_0NOTEQUAL),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_0notequal_fails_empty_stack() {
    // OP_0NOTEQUAL should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_0NOTEQUAL)]);
    assert!(!script.interpret());
}
