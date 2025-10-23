use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L451

#[test]
pub fn test_op_if_true_branch() {
    // IF with true condition should execute the branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_IF),    // Start IF
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_if_false_branch() {
    // IF with false condition should skip the branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_IF),    // Start IF
        Term::Instruction(Opcode::OP_5),     // This is skipped
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_1),     // Push 1 (should be on top)
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_if_with_else() {
    // IF...ELSE...ENDIF should execute the correct branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_IF),    // Start IF
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ELSE),  // ELSE
        Term::Instruction(Opcode::OP_7),     // This is skipped
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_if_else_false_branch() {
    // IF...ELSE with false condition should execute ELSE branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_IF),    // Start IF
        Term::Instruction(Opcode::OP_5),     // This is skipped
        Term::Instruction(Opcode::OP_ELSE),  // ELSE
        Term::Instruction(Opcode::OP_7),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End IF
        Term::Instruction(Opcode::OP_7),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_if_nested() {
    // Nested IF statements should work correctly
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_IF),    // Outer IF
        Term::Instruction(Opcode::OP_1),     // Push true
        Term::Instruction(Opcode::OP_IF),    // Inner IF
        Term::Instruction(Opcode::OP_5),     // This executes
        Term::Instruction(Opcode::OP_ENDIF), // End inner IF
        Term::Instruction(Opcode::OP_ENDIF), // End outer IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_if_fails_empty_stack() {
    // IF should fail when stack is empty
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_ENDIF),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_if_fails_missing_endif() {
    // IF without ENDIF should fail (unbalanced)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_5),
    ]);
    assert!(!script.interpret());
}
