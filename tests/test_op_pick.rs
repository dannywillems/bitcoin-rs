use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L580

#[test]
pub fn test_op_pick_zero() {
    // PICK 0 should copy the top item
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_4),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_0),    // n = 0
        Term::Instruction(Opcode::OP_PICK), // Copies top item (3)
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_pick_two() {
    // PICK 2 should copy the 3rd item from top
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_2),    // n = 2
        Term::Instruction(Opcode::OP_PICK), // Copies item at index 2 from top (1)
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_pick_fails_empty_stack() {
    // PICK should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_PICK)]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_pick_fails_insufficient_depth() {
    // PICK should fail when n is too large
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2), // Only 2 items
        Term::Instruction(Opcode::OP_3), // Try to pick item at index 3
        Term::Instruction(Opcode::OP_PICK),
    ]);
    assert!(!script.interpret());
}
