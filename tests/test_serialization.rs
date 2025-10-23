use bincode::{deserialize, serialize};
use bitcoin_rs::script::{Opcode, Script, Term};
use hex;

#[test]
pub fn test_to_bytes() {
    // P2PKH
    {
        let data = "3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401";
        let hex_data: Vec<u8> = hex::decode(data).unwrap();
        let data2 = "03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31";
        let hex_data2: Vec<u8> = hex::decode(data2).unwrap();
        let script = Script::new(vec![
            Term::Instruction(Opcode::OP_PUSHBYTES(72)),
            Term::Data(hex_data),
            Term::Instruction(Opcode::OP_PUSHBYTES(33)),
            Term::Data(hex_data2),
        ]);

        let exp_output = "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }
    // P2PK
    {
        let data = "30440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01";
        let data: Vec<u8> = hex::decode(data).unwrap();
        let script = Script::new(vec![
            Term::Instruction(Opcode::OP_PUSHBYTES(71)),
            Term::Data(data),
        ]);
        let exp_output = "4730440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }
    // P2MS
    {
        let data = "304502204aa764d2b30f572cc4ef17c8ed8536c46f595a08ba41a611b14f32c60282c150022100ede45011be565dc225cc9be292638cf7270b129934fe8758634716b8f7a34c0701";
        let data = hex::decode(data).unwrap();
        let script = Script::new(vec![
            Term::Instruction(Opcode::OP_0),
            Term::Instruction(Opcode::OP_PUSHBYTES(72)),
            Term::Data(data),
        ]);
        let exp_output = "0048304502204aa764d2b30f572cc4ef17c8ed8536c46f595a08ba41a611b14f32c60282c150022100ede45011be565dc225cc9be292638cf7270b129934fe8758634716b8f7a34c0701";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }
    // P2SH
    {
        let data = "3044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401";
        let data = hex::decode(data).unwrap();

        let data2 = "5121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae";
        let data2 = hex::decode(data2).unwrap();
        let script = Script::new(vec![
            Term::Instruction(Opcode::OP_0),
            Term::Instruction(Opcode::OP_PUSHBYTES(71)),
            Term::Data(data),
            Term::Instruction(Opcode::OP_PUSHBYTES(71)),
            Term::Data(data2),
        ]);
        let exp_output = "00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }
    // Genesis bloc - coinbase
    {
        let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
        let data = hex::decode(data).unwrap();
        let script = Script::new(vec![
            Term::Instruction(Opcode::OP_PUSHBYTES(4)),
            Term::Data(hex::decode("ffff001d").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(1)),
            Term::Data(hex::decode("04").unwrap()),
            Term::Instruction(Opcode::OP_PUSHBYTES(69)),
            Term::Data(data),
        ]);
        let exp_output = "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
        let exp_output = hex::decode(exp_output).unwrap();
        assert_eq!(exp_output, script.to_bytes());
    }
}

#[test]
pub fn test_script_of_bytes() {
    let asm_hex = "76a91455ae51684c43435da751ac8d2173b2652eb6410588ac";
    let script = hex::decode(asm_hex).unwrap();
    let exp_script = Script::new(vec![
        Term::Instruction(Opcode::OP_DUP),
        Term::Instruction(Opcode::OP_HASH160),
        Term::Instruction(Opcode::OP_PUSHBYTES(20)),
        Term::Data(vec![
            85, 174, 81, 104, 76, 67, 67, 93, 167, 81, 172, 141, 33, 115, 178, 101, 46, 182, 65, 5,
        ]),
        Term::Instruction(Opcode::OP_EQUALVERIFY),
        Term::Instruction(Opcode::OP_CHECKSIG),
    ]);
    assert_eq!(Script::of_bytes(script), exp_script)
}

#[test]
pub fn test_decode_pushdata1() {
    let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA1(0x4c)),
        Term::Data(data),
    ]);
    let exp_output = "4c4caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let exp_output = hex::decode(exp_output).unwrap();
    assert_eq!(exp_output, script.to_bytes());
}

#[test]
pub fn test_decode_pushdata2() {
    let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA2([0x00, 0x01])),
        Term::Data(data),
    ]);
    let exp_output = "4d0001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let exp_output = hex::decode(exp_output).unwrap();
    assert_eq!(exp_output, script.to_bytes());
}

#[test]
pub fn test_decode_pushdata4() {
    let data = "ab".repeat(1 << 16);
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA4([0x00, 0x00, 0x01, 0x00])),
        Term::Data(hex::decode(data).unwrap()),
    ]);
    script.to_bytes();
    assert_eq!(script.to_bytes().len(), 5 + (1 << 16))
}

#[test]
pub fn test_serialize_and_deserialize() {
    let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(hex::decode("ffff001d").unwrap()),
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(hex::decode("04").unwrap()),
        Term::Instruction(Opcode::OP_PUSHBYTES(69)),
        Term::Data(data),
    ]);
    // Checking serialize/deserialize works together
    let res: Vec<u8> = serialize(&script).unwrap();
    let script2: Script = deserialize(&res).unwrap();
    assert_eq!(script, script2);
}

#[test]
pub fn test_serialize_and_deserialize_pushdata1() {
    let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA1(0x4c)),
        Term::Data(data),
    ]);
    // Checking serialize/deserialize works together
    let res: Vec<u8> = serialize(&script).unwrap();
    let script2: Script = deserialize(&res).unwrap();
    assert_eq!(script, script2);
}

#[test]
pub fn test_serialize_and_deserialize_pushdata2() {
    let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA2([0x00, 0x01])),
        Term::Data(data),
    ]);
    // Checking serialize/deserialize works together
    let res: Vec<u8> = serialize(&script).unwrap();
    let script2: Script = deserialize(&res).unwrap();
    assert_eq!(script, script2);
}

#[test]
pub fn test_serialize_and_deserialize_pushdata4() {
    let data = "ab".repeat(1 << 16);
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHDATA4([0x00, 0x00, 0x01, 0x00])),
        Term::Data(hex::decode(data).unwrap()),
    ]);
    // Checking serialize/deserialize works together
    let res: Vec<u8> = serialize(&script).unwrap();
    let script2: Script = deserialize(&res).unwrap();
    assert_eq!(script, script2);
}

// FIXME: ignore if riscv32i
#[test]
pub fn test_display_asm() {
    let data = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
    let data = hex::decode(data).unwrap();
    let script = Script::new(vec![
        Term::Instruction(Opcode::OP_PUSHBYTES(4)),
        Term::Data(hex::decode("ffff001d").unwrap()),
        Term::Instruction(Opcode::OP_PUSHBYTES(1)),
        Term::Data(hex::decode("04").unwrap()),
        Term::Instruction(Opcode::OP_PUSHBYTES(69)),
        Term::Data(data),
    ]);

    assert_eq!(
        script.to_string(),
        "OP_PUSHBYTES4 0xffff001d OP_PUSHBYTES1 0x04 OP_PUSHBYTES69 0x5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
    );
}

#[test]
pub fn test_interpreter_p2pkh() {
    let _tx = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
    let sig = "47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b330701";
    let redeem_script = "2102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34e";
    let asm_hex = "76a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac";
    let mut res = sig.to_owned();
    res.push_str(redeem_script);
    res.push_str(asm_hex);
    let script = Script::of_bytes(hex::decode(res).unwrap());
    assert!(script.interpret());
}
