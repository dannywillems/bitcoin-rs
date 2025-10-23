use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L451

#[test]
pub fn test_op_notif_false_branch() {
    // NOTIF with false condition should execute the branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_NOTIF), // Start NOTIF (inverted, so true)
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End NOTIF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_notif_true_branch() {
    // NOTIF with true condition should skip the branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_NOTIF), // Start NOTIF (inverted, so false)
        Term::Instruction(Opcode::OP_5),     // This is skipped
        Term::Instruction(Opcode::OP_ENDIF), // End NOTIF
        Term::Instruction(Opcode::OP_1),     // Push 1 (should be on top)
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_notif_with_else() {
    // NOTIF...ELSE...ENDIF should execute the correct branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_NOTIF), // Start NOTIF (inverted, so true)
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ELSE),  // ELSE
        Term::Instruction(Opcode::OP_7),     // This is skipped
        Term::Instruction(Opcode::OP_ENDIF), // End NOTIF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_notif_else_true_condition() {
    // NOTIF...ELSE with true condition should execute ELSE branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_NOTIF), // Start NOTIF (inverted, so false)
        Term::Instruction(Opcode::OP_5),     // This is skipped
        Term::Instruction(Opcode::OP_ELSE),  // ELSE
        Term::Instruction(Opcode::OP_7),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End NOTIF
        Term::Instruction(Opcode::OP_7),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_notif_fails_empty_stack() {
    // NOTIF should fail when stack is empty
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_NOTIF),
        Term::Instruction(Opcode::OP_ENDIF),
    ]);
    assert!(!script.interpret());
}
