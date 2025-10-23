use bitcoin_rs::script::{Opcode, Script, Term};

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L567

#[test]
pub fn test_op_depth_empty_stack() {
    // DEPTH on empty stack should push 0 (as 4-byte little-endian)
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_DEPTH),
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(vec![0, 0, 0, 0]), // 0 in little-endian u32
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_depth_with_items() {
    // DEPTH should return the number of items on stack
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_1),
        Term::Instruction(Opcode::OP_2),
        Term::Instruction(Opcode::OP_3),
        Term::Instruction(Opcode::OP_DEPTH),
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(vec![3, 0, 0, 0]), // Depth of 3 in little-endian
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_depth_includes_itself() {
    // DEPTH pushes a value, so subsequent DEPTH includes it
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_DEPTH), // Pushes 0
        Term::Instruction(Opcode::OP_DEPTH), // Pushes 1 (includes previous depth)
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(vec![1, 0, 0, 0]), // Should be 1
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}
