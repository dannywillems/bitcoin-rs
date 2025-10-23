.PHONY: help
help: ## Show this help message
	@echo "Bitcoin-RS Makefile"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

.PHONY: build
build: ## Build with all targets and features
	cargo build --all-targets --all-features

.PHONY: release
release: ## Build in release mode with all targets and features
	cargo build --release --all-targets --all-features

.PHONY: test-doc
test-doc: ## Test documentation examples
	cargo test --all-features --release --doc

.PHONY: test-all
test-all: ## Run all tests with release optimizations
	cargo test --all-features --release $(CARGO_EXTRA_ARGS) -- \
		--nocapture $(BIN_EXTRA_ARGS)

.PHONY: format
format: ## Format Rust code (requires nightly)
	cargo +nightly fmt

.PHONY: format-check
format-check: ## Check Rust code formatting without modifying
	cargo +nightly fmt -- --check

.PHONY: format-md
format-md: ## Format all markdown files with prettier
	npx prettier --write '**/*.md'

.PHONY: format-md-check
format-md-check: ## Check markdown formatting without modifying
	npx prettier --check '**/*.md'

.PHONY: lint
lint: ## Run clippy with strict warnings
	cargo clippy --all-features --all-targets --tests \
		$(CARGO_EXTRA_ARGS) -- -W clippy::all -D warnings

.PHONY: setup-toolchain-riscv32i
setup-toolchain-riscv32i: ## Install RISC-V 32-bit toolchain
	rustup target add "riscv32i-unknown-none-elf"

.PHONY: build-riscv32i
build-riscv32i: setup-toolchain-riscv32i ## Build for RISC-V target
	cargo build --release --target "riscv32i-unknown-none-elf" \
		--all-features

.PHONY: generate-doc
generate-doc: ## Generate documentation
	@echo ""
	@echo "Generating the documentation."
	@echo ""
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
	@echo ""
	@echo "The documentation is available at: ./target/doc"
	@echo ""
