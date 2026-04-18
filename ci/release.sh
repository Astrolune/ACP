#!/bin/bash
set -e

echo "=== ACP Release Script ==="

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version>"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Preparing release $VERSION${NC}"

# Update version in all Cargo.toml files
echo -e "${BLUE}Updating versions...${NC}"
sed -i "s/^version = .*/version = \"$VERSION\"/" Cargo.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" crates/*/Cargo.toml

# Run tests
echo -e "${BLUE}Running tests...${NC}"
./ci/test.sh

# Build release artifacts
echo -e "${BLUE}Building release artifacts...${NC}"
cargo build --release --all-features

# Create git tag
echo -e "${BLUE}Creating git tag...${NC}"
git add .
git commit -m "Release v$VERSION"
git tag -a "v$VERSION" -m "Release v$VERSION"

echo -e "${GREEN}✓ Release prepared${NC}"
echo ""
echo "Next steps:"
echo "  1. Review changes: git show"
echo "  2. Push: git push origin main --tags"
echo "  3. GitHub Actions will handle the rest"
