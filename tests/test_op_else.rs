use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L464

#[test]
pub fn test_op_else_switches_branches() {
    // ELSE should switch from executing to skipping
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_IF),    // Start IF (executing)
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ELSE),  // Switch to skipping
        Term::Instruction(Opcode::OP_7),     // This is skipped
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_else_switches_from_skipping() {
    // ELSE should switch from skipping to executing
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_IF),    // Start IF (skipping)
        Term::Instruction(Opcode::OP_7),     // This is skipped
        Term::Instruction(Opcode::OP_ELSE),  // Switch to executing
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_else_fails_without_if() {
    // ELSE without IF should fail
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_ELSE),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_else_after_endif_fails() {
    // ELSE after ENDIF should fail
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_ELSE), // This is invalid
        Term::Instruction(Opcode::OP_ENDIF),
    ]);
    assert!(!script.interpret());
}
