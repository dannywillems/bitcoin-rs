use bitcoin_rs::script::{Opcode, Script, Term};
use hex;

// Reference: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/interpreter.cpp#L920

#[test]
pub fn test_op_sha256() {
    // SHA256 of empty data should give known hash
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(0)),
        Term::Data(vec![]),
        Term::Instruction(Opcode::OP_SHA256),
        Term::Instruction(Opcode::OP_PUSHBYTES(32)),
        Term::Data(
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap(),
        ),
        Term::Instruction(Opcode::OP_EQUAL),
    ]);
    assert!(script.interpret());
}

#[test]
pub fn test_op_sha256_fails_empty_stack() {
    // OP_SHA256 should fail when stack is empty
    let script = Script::new(vec![Term::Instruction(Opcode::OP_SHA256)]);
    assert!(!script.interpret());
}
