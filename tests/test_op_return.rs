use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L499

#[test]
pub fn test_op_return_fails() {
    // OP_RETURN should always fail
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_RETURN),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_return_fails_immediately() {
    // OP_RETURN should fail even if it's the first instruction
    let script = Script::new(vec![Term::Instruction(Opcode::OP_RETURN)]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_return_in_unexecuted_branch() {
    // OP_RETURN in an unexecuted IF branch should be skipped
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),      // Push false
        Term::Instruction(Opcode::OP_IF),     // Start IF (skipping)
        Term::Instruction(Opcode::OP_RETURN), // This is skipped
        Term::Instruction(Opcode::OP_ENDIF),  // End IF
        Term::Instruction(Opcode::OP_1),      // This executes
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_return_in_executed_branch() {
    // OP_RETURN in an executed IF branch should fail
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),      // Push true
        Term::Instruction(Opcode::OP_IF),     // Start IF (executing)
        Term::Instruction(Opcode::OP_RETURN), // This executes and fails
        Term::Instruction(Opcode::OP_ENDIF),  // Never reached
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}
