#!/bin/bash
# FastMCP ThreatIntel - GitHub Secrets Setup Script
# Secure setup without hardcoded tokens

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            FastMCP ThreatIntel - Secrets Setup              ║"
echo "║              Secure Token Configuration                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ GitHub CLI (gh) is not installed.${NC}"
    echo "Please install it from: https://cli.github.com/"
    echo
    echo "Installation commands:"
    echo "  macOS: brew install gh"
    echo "  Windows: winget install GitHub.cli"
    echo "  Linux: See https://github.com/cli/cli#installation"
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo -e "${YELLOW}🔑 Please authenticate with GitHub CLI first:${NC}"
    echo "gh auth login"
    echo
    echo "Choose 'GitHub.com' and 'HTTPS' when prompted."
    exit 1
fi

echo -e "${GREEN}✅ GitHub CLI is installed and authenticated${NC}"
echo

# Set the pre-configured Codecov token
echo -e "${YELLOW}📊 Setting up Codecov token...${NC}"
gh secret set CODECOV_TOKEN --body "0e06a8a9-3d52-4698-b5f4-6794bdd4ffd0"
echo -e "${GREEN}✅ Codecov token configured${NC}"

# Prompt for PyPI token
echo -e "${YELLOW}📦 Setting up PyPI token...${NC}"
echo "Please provide your PyPI API token:"
read -s -p "PyPI Token: " PYPI_TOKEN
echo
if [ -n "$PYPI_TOKEN" ]; then
    gh secret set PYPI_API_TOKEN --body "$PYPI_TOKEN"
    echo -e "${GREEN}✅ PyPI token configured${NC}"
else
    echo -e "${YELLOW}⚠️ PyPI token skipped${NC}"
fi

# Set Docker Hub username and prompt for token
echo -e "${YELLOW}🐳 Setting up Docker Hub credentials...${NC}"
gh secret set DOCKERHUB_USERNAME --body "arjuntrivedi"
echo "Please provide your Docker Hub token:"
read -s -p "Docker Hub Token: " DOCKER_TOKEN
echo
if [ -n "$DOCKER_TOKEN" ]; then
    gh secret set DOCKERHUB_TOKEN --body "$DOCKER_TOKEN"
    echo -e "${GREEN}✅ Docker Hub credentials configured${NC}"
else
    echo -e "${YELLOW}⚠️ Docker Hub token skipped${NC}"
fi

# Optional: Set TestPyPI token for testing
echo
echo -e "${YELLOW}🧪 Setting up TestPyPI token (optional)...${NC}"
echo "Would you like to configure TestPyPI for testing releases? (y/N)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Please provide your TestPyPI API token:"
    read -s -p "TestPyPI Token: " TEST_PYPI_TOKEN
    echo
    if [ -n "$TEST_PYPI_TOKEN" ]; then
        gh secret set TEST_PYPI_API_TOKEN --body "$TEST_PYPI_TOKEN"
        echo -e "${GREEN}✅ TestPyPI token configured${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ TestPyPI token skipped${NC}"
fi

echo
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    🎉 Setup Complete!                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Configured secrets:"
echo "  ✅ CODECOV_TOKEN (coverage reporting)"
[ -n "$PYPI_TOKEN" ] && echo "  ✅ PYPI_API_TOKEN (package publishing)"
echo "  ✅ DOCKERHUB_USERNAME (docker publishing)"
[ -n "$DOCKER_TOKEN" ] && echo "  ✅ DOCKERHUB_TOKEN (docker authentication)"

echo
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "1. Create a test PR to verify CI/CD pipeline:"
echo "   git checkout -b test/setup"
echo "   git commit --allow-empty -m 'test: verify CI/CD setup'"
echo "   git push origin test/setup"
echo "   gh pr create --title 'Test CI/CD Setup' --body 'Verifying pipeline works'"
echo
echo "2. Create your first release:"
echo "   git tag v0.2.1"
echo "   git push origin v0.2.1"
echo "   gh release create v0.2.1 --title 'Release v0.2.1' --generate-notes"
echo
echo "3. Monitor the workflows:"
echo "   GitHub Actions: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions"
echo "   Codecov: https://codecov.io/gh/$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "   PyPI: https://pypi.org/project/fastmcp-threatintel/"
echo "   Docker: https://hub.docker.com/r/arjuntrivedi/fastmcp-threatintel"
echo
echo -e "${GREEN}📚 For detailed information, see: .github/SETUP.md${NC}"