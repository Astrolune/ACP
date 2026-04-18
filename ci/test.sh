#!/bin/bash
set -e

echo "=== ACP Test Script ==="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Run Rust tests
echo -e "${BLUE}Running Rust tests...${NC}"
cargo test --all-features --workspace

# Run clippy
echo -e "${BLUE}Running clippy...${NC}"
cargo clippy --all-targets --all-features -- -D warnings

# Check formatting
echo -e "${BLUE}Checking formatting...${NC}"
cargo fmt --all -- --check

# Run examples
echo -e "${BLUE}Running examples...${NC}"
cargo run --example basic_encryption
cargo run --example key_derivation
cargo run --example session_management

# Build C examples
if command -v cmake &> /dev/null; then
    echo -e "${BLUE}Building C examples...${NC}"
    cd examples/c
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    cd ../..
fi

echo -e "${GREEN}✓ All tests passed${NC}"
