use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L589

#[test]
pub fn test_op_roll_zero() {
    // ROLL 0 should move the top item to top (no-op)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_0),    // n = 0
        Term::Instruction(Opcode::OP_ROLL), // Moves top to top (no change)
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_roll_two() {
    // ROLL 2 should move 3rd item to top
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_2),    // n = 2
        Term::Instruction(Opcode::OP_ROLL), // Moves item at index 2 to top (1)
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_roll_removes_item() {
    // ROLL should remove the item from its original position
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_6),
        Term::Instruction(Opcode::OP_7),
        Term::Instruction(Opcode::OP_1),    // n = 1
        Term::Instruction(Opcode::OP_ROLL), // Moves 6 to top, stack is now: 5, 7, 6
        Term::Instruction(Opcode::OP_6),
        Term::Instruction(Opcode::OP_EQUAL),
        Term::Instruction(Opcode::OP_VERIFY),
        Term::Instruction(Opcode::OP_7),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_roll_fails_empty_stack() {
    // ROLL should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_ROLL)]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_roll_fails_insufficient_depth() {
    // ROLL should fail when n is too large
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2), // Only 2 items
        Term::Instruction(Opcode::OP_3), // Try to roll item at index 3
        Term::Instruction(Opcode::OP_ROLL),
    ]);
    assert!(!script.interpret());
}
