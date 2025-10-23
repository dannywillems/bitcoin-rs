# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

bitcoin-rs is a Bitcoin client written in Rust without std library dependencies.
The primary goal is to enable running a light client in zkVMs like o1vm to
provide a bridge from Bitcoin to Mina and enable value settlements between the
two chains.

## Key Technologies

- **Language**: Rust (edition 2021)
- **Target**: no_std compatible for zkVM deployment
- **Special Target**: RISC-V 32-bit (riscv32i-unknown-none-elf)
- **Reference**: Based on Bitcoin Core commit
  cac846c2fbf6fc69bfc288fd387aa3f68d84d584

## Architecture

The codebase follows Bitcoin Core's architecture with a focus on no_std
compatibility:

- **Script System**: Central to Bitcoin transaction validation
  - `Opcode`: 150+ opcodes representing Bitcoin Script operations
  - `Term`: AST nodes - either opcodes or data to be pushed (`Term::Opcode` /
    `Term::Data`)
  - `Script`: Wrapper around `Vec<Term>` with serialization/deserialization
  - `Stack`: Simple stack machine (`Vec<Vec<u8>>`) for script execution

- **Serialization**: Custom implementations throughout for no_std compatibility
  - Most types implement serde `Serialize`/`Deserialize` manually
  - `CompactBytes` utility handles Bitcoin's variable-length integer encoding
  - Binary format matches Bitcoin Core exactly for compatibility

- **Transaction Model**:
  - `Transaction`: Contains inputs, outputs, version, lock_time
  - `TransactionInput`: References UTXO via txid/vout, includes scriptSig
  - `TransactionOutput`: Contains amount and scriptPubKey

- **Address Types**: P2PKH and P2SH variants (in `address.rs`)

- **Signature Handling**: Supports different signature hash types (ALL, NONE,
  SINGLE, etc.)

## Common Development Commands

### Building

- `make build` - Build with all targets and features
- `make release` - Release build with all targets and features
- `make build-riscv32i` - Build for RISC-V target (requires
  setup-toolchain-riscv32i)

### Testing

- `make test-all` - Run all tests with release optimizations and full output
- `make test-doc` - Test documentation examples
- `cargo test --all-features --release <test_name>` - Run a specific test by
  name
- `cargo test --all-features --release --lib` - Run only library tests (no doc
  tests)

### Code Quality

- `make format` - Format Rust code (requires nightly toolchain)
- `make format-check` - Check Rust code formatting without modifying
- `make format-md` - Format all markdown files with prettier (80 char wrap)
- `make format-md-check` - Check markdown formatting without modifying
- `make lint` - Run clippy linter with strict warnings (all warnings treated as
  errors)

### Documentation

- `make generate-doc` - Generate documentation (available at ./target/doc)

### Cleanup

- `make clean` - Clean build artifacts

## Development Constraints

- **no_std environment**: Cannot use standard library (no std::io, std::fs,
  etc.)
  - Use `alloc` feature for heap allocations (Vec, String, etc.)
  - Avoid println! in production code (ok in tests with #[cfg(test)])
- **Serialization**: Must match Bitcoin Core's binary format exactly
  - Implement serde traits manually when needed for precise control
  - Use `bincode` for deserialization with length prefixes
- **zkVM optimization**: Code must be efficient for RISC-V zkVM execution
  - Release builds use LTO and panic='abort' for minimal binary size
- **Quality gates**: All clippy warnings and doc warnings are errors
- **Rust formatting**: Always run `make format` after modifying any Rust file
- **Markdown formatting**: Always run `make format-md` after editing any
  markdown file
- **Testing requirement**: For each opcode implementation, a corresponding unit
  test must be implemented
- **Opcode documentation**: Each opcode in the enum definition must document:
  - Instruction side effects (stack changes, state modifications)
  - Semantic behavior (what the opcode does and when)

## Missing Opcode Implementations

The `interpreter.rs` file is currently empty. All opcodes defined in `script.rs`
need implementation:

### Push Value Opcodes

- OP_0 / OP_FALSE
- OP_PUSHBYTES(u8)
- OP_PUSHDATA1(u8)
- OP_PUSHDATA2([u8; 2])
- OP_PUSHDATA4([u8; 4])
- OP_1NEGATE
- OP_1 / OP_TRUE
- OP_2 through OP_16

### Control Flow Opcodes

- OP_NOP
- OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF
- OP_VERIFY
- OP_RETURN

### Stack Manipulation Opcodes

- OP_TOALTSTACK / OP_FROMALTSTACK
- OP_2DROP / OP_2DUP / OP_3DUP
- OP_2OVER / OP_2ROT / OP_2SWAP
- OP_IFDUP / OP_DEPTH / OP_DROP / OP_DUP
- OP_NIP / OP_OVER / OP_PICK / OP_ROLL
- OP_ROT / OP_SWAP / OP_TUCK

### Splice Opcodes (Disabled)

- OP_CAT / OP_SUBSTR / OP_LEFT / OP_RIGHT (disabled)
- OP_SIZE

### Bit Logic Opcodes

- OP_INVERT / OP_AND / OP_OR / OP_XOR (disabled)
- OP_EQUAL / OP_EQUALVERIFY

### Numeric Opcodes

- OP_1ADD / OP_1SUB
- OP_2MUL / OP_2DIV (disabled)
- OP_NEGATE / OP_ABS / OP_NOT / OP_0NOTEQUAL
- OP_ADD / OP_SUB / OP_MUL / OP_DIV / OP_MOD
- OP_LSHIFT / OP_RSHIFT (disabled)
- OP_BOOLAND / OP_BOOLOR
- OP_NUMEQUAL / OP_NUMEQUALVERIFY / OP_NUMNOTEQUAL
- OP_LESSTHAN / OP_GREATERTHAN
- OP_LESSTHANOREQUAL / OP_GREATERTHANOREQUAL
- OP_MIN / OP_MAX / OP_WITHIN

### Cryptographic Opcodes

- OP_RIPEMD160 / OP_SHA1 / OP_SHA256
- OP_HASH160 / OP_HASH256
- OP_CODESEPARATOR
- OP_CHECKSIG / OP_CHECKSIGVERIFY
- OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
- OP_CHECKSIGADD (BIP 342 Tapscript)

### Locktime Opcodes

- OP_CHECKLOCKTIMEVERIFY (BIP 65)
- OP_CHECKSEQUENCEVERIFY (BIP 112)

### Reserved/Invalid Opcodes

- OP_RESERVED / OP_VER / OP_VERIF / OP_VERNOTIF
- OP_RESERVED1 / OP_RESERVED2
- OP_NOP1 through OP_NOP10
- OP_INVALIDOPCODE
