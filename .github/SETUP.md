# GitHub Repository Setup Guide

This guide helps you configure the necessary secrets and settings for the FastMCP ThreatIntel repository to enable full CI/CD functionality.

## 🔐 Pre-configured Credentials

The following credentials need to be configured for this repository:

### 1. Codecov Integration
- **Secret Name**: `CODECOV_TOKEN`
- **Status**: ⚠️ Contact repository owner for token

### 2. PyPI Publishing
- **Secret Name**: `PYPI_API_TOKEN`
- **Status**: ⚠️ Contact repository owner for token

### 3. Docker Hub Publishing
- **Secret Name**: `DOCKERHUB_TOKEN`
- **Status**: ⚠️ Contact repository owner for token

## 🛠️ Quick Setup Commands

### Set All Secrets at Once
```bash
# Install GitHub CLI if not already installed
gh auth login

# Set pre-configured secrets (get actual tokens from repository owner)
gh secret set CODECOV_TOKEN --body "your_codecov_token_here"
gh secret set PYPI_API_TOKEN --body "your_pypi_token_here"
gh secret set DOCKERHUB_TOKEN --body "your_docker_token_here"

echo "✅ All secrets configured successfully!"
```

## 📋 Repository Settings

### 1. Branch Protection Rules
Enable branch protection for `main`:
1. Go to **Settings** → **Branches**
2. Add rule for `main` branch
3. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Include administrators

### 2. GitHub Pages (for Documentation)
1. Go to **Settings** → **Pages**
2. Source: **Deploy from a branch**
3. Branch: **gh-pages** (will be created by CI)
4. Folder: **/ (root)**

### 3. Actions Permissions
1. Go to **Settings** → **Actions** → **General**
2. Actions permissions: **Allow all actions and reusable workflows**
3. Workflow permissions: **Read and write permissions**
4. Enable: ✅ **Allow GitHub Actions to create and approve pull requests**

## 🚀 Testing the Setup

### 1. Test CI Pipeline
```bash
# Create a test branch and push
git checkout -b test/ci-setup
git commit --allow-empty -m "test: CI pipeline setup"
git push origin test/ci-setup

# Create a PR to trigger the full pipeline
gh pr create --title "Test CI Setup" --body "Testing CI/CD pipeline"
```

### 2. Test Release Process
```bash
# Create a test release
git tag v0.2.1
git push origin v0.2.1

# Create release via GitHub
gh release create v0.2.1 --title "Release v0.2.1" --generate-notes
```

## 🔍 Monitoring

### CI/CD Status
- **GitHub Actions**: [Repository Actions](https://github.com/4R9UN/fastmcp-threatintel/actions)
- **Codecov**: [Coverage Dashboard](https://codecov.io/gh/4R9UN/fastmcp-threatintel)
- **PyPI**: [Package Page](https://pypi.org/project/fastmcp-threatintel/)
- **Docker Hub**: [Image Repository](https://hub.docker.com/r/arjuntrivedi/fastmcp-threatintel)

### Status Badges
```markdown
[![CI/CD Pipeline](https://github.com/4R9UN/fastmcp-threatintel/actions/workflows/ci.yml/badge.svg)](https://github.com/4R9UN/fastmcp-threatintel/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/4R9UN/fastmcp-threatintel/branch/main/graph/badge.svg?token=your_codecov_token_here)](https://codecov.io/gh/4R9UN/fastmcp-threatintel)
[![PyPI version](https://badge.fury.io/py/fastmcp-threatintel.svg)](https://badge.fury.io/py/fastmcp-threatintel)
[![Docker Pulls](https://img.shields.io/docker/pulls/arjuntrivedi/fastmcp-threatintel)](https://hub.docker.com/r/arjuntrivedi/fastmcp-threatintel)