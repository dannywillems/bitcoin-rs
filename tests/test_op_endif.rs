use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L467

#[test]
pub fn test_op_endif_closes_if() {
    // ENDIF should properly close IF block
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_endif_closes_notif() {
    // ENDIF should properly close NOTIF block
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),
        Term::Instruction(Opcode::OP_NOTIF),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_endif_fails_without_if() {
    // ENDIF without IF should fail
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_endif_nested() {
    // Nested IF blocks should require matching ENDIFs
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_IF),
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_ENDIF), // Closes inner IF
        Term::Instruction(Opcode::OP_ENDIF), // Closes outer IF
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}
