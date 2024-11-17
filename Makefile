# Clean the project
clean:
	cargo clean

# Build the project
build:
	cargo build --all-targets --all-features

# Build the project in release mode
release:
	cargo build --release --all-targets --all-features

# Test the project's docs comments
test-doc:
	cargo test --all-features --release --doc

# Test the project with all tests and using native cargo test runner
test-all:
	cargo test --all-features --release $(CARGO_EXTRA_ARGS) -- --nocapture $(BIN_EXTRA_ARGS)

# Format the code
format:
	cargo +nightly fmt -- --check

# Lint the code
lint:
	cargo clippy --all-features --all-targets --tests $(CARGO_EXTRA_ARGS) -- -W clippy::all -D warnings

setup-toolchain-riscv32i:
	rustup target add "riscv32i-unknown-none-elf"

build-riscv32i: setup-toolchain-riscv32i
	cargo build --release --target "riscv32i-unknown-none-elf" --all-features

generate-doc:
		@echo ""
		@echo "Generating the documentation."
		@echo ""
		RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
		@echo ""
		@echo "The documentation is available at: ./target/doc"
		@echo ""

.PHONY: all clean build release test-doc test-all format lint setup-toolchain-riscv32i build-riscv32i generate-doc
