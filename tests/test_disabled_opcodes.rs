use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L360

// VERIF and VERNOTIF tests - these fail even in unexecuted branches

#[test]
pub fn test_op_verif_always_fails() {
    // VERIF should always fail, even in unexecuted branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),     // Push false
        Term::Instruction(Opcode::OP_IF),    // Start IF (not executing)
        Term::Instruction(Opcode::OP_VERIF), // Should still fail
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_vernotif_always_fails() {
    // VERNOTIF should always fail, even in unexecuted branch
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),        // Push false
        Term::Instruction(Opcode::OP_IF),       // Start IF (not executing)
        Term::Instruction(Opcode::OP_VERNOTIF), // Should still fail
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

// Reserved opcodes - fail when executed

#[test]
pub fn test_op_reserved_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_RESERVED),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_ver_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_VER),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_reserved1_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_RESERVED1),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_reserved2_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_RESERVED2),
        Term::Instruction(Opcode::OP_1),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_reserved_ok_in_unexecuted_branch() {
    // Reserved opcodes are OK in unexecuted branches
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),        // Push false
        Term::Instruction(Opcode::OP_IF),       // Start IF (not executing)
        Term::Instruction(Opcode::OP_RESERVED), // This is skipped, so OK
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_1), // Script succeeds
    ]);
    assert!(script.interpret());
}

// Disabled string opcodes

#[test]
pub fn test_op_cat_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_CAT),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_substr_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_SUBSTR),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_left_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_LEFT),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_right_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_RIGHT),
    ]);
    assert!(!script.interpret());
}

// Disabled bitwise opcodes

#[test]
pub fn test_op_invert_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_INVERT),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_and_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_AND),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_or_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_OR),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_xor_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_XOR),
    ]);
    assert!(!script.interpret());
}

// Disabled numeric opcodes

#[test]
pub fn test_op_2mul_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_2MUL),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_2div_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_2DIV),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_mul_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_MUL),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_div_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_6),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_DIV),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_mod_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_5),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_MOD),
    ]);
    assert!(!script.interpret());
}

// Disabled bit shift opcodes

#[test]
pub fn test_op_lshift_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_LSHIFT),
    ]);
    assert!(!script.interpret());
}

#[test]
pub fn test_op_rshift_fails() {
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_4),
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_RSHIFT),
    ]);
    assert!(!script.interpret());
}

// Test that disabled opcodes are OK in unexecuted branches

#[test]
pub fn test_disabled_ok_in_unexecuted_branch() {
    // Disabled opcodes are OK in unexecuted branches
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_0),   // Push false
        Term::Instruction(Opcode::OP_IF),  // Start IF (not executing)
        Term::Instruction(Opcode::OP_CAT), // This is skipped
        Term::Instruction(Opcode::OP_MUL), // This is skipped
        Term::Instruction(Opcode::OP_ENDIF),
        Term::Instruction(Opcode::OP_1), // Script succeeds
    ]);
    assert!(script.interpret());
}
