#!/bin/bash
set -e

echo "=== ACP Build Script ==="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building all crates...${NC}"
cargo build --release --all-features

echo -e "${BLUE}Building FFI library...${NC}"
cargo build --release -p acp-ffi

echo -e "${BLUE}Generating C headers...${NC}"
cargo build -p acp-ffi

echo -e "${GREEN}✓ Build complete${NC}"
echo ""
echo "Artifacts:"
echo "  - Rust libraries: target/release/"
echo "  - C headers: crates/acp-ffi/include/acp.h"
echo "  - FFI library: target/release/libacp.{so,dll,dylib}"
