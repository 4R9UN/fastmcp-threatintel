# 🧪 Development Guide

## Setup Development Environment

```bash
# Clone repository
git clone https://github.com/4R9UN/fastmcp-threatintel.git
cd fastmcp-threatintel

# Install with development dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install

# Run tests
uv run pytest

# Type checking
uv run mypy src/

# Code formatting
uv run ruff format src/ tests/
```

## Testing

```bash
# Run all tests with coverage
uv run pytest --cov=src/threatintel --cov-report=html

# Run specific test categories
uv run pytest tests/unit/
uv run pytest tests/integration/ -v
uv run pytest -m "not slow"

# Performance tests
uv run pytest tests/performance/ --benchmark-only
```

## Building

```bash
# Build package
uv build

# Build Docker image
docker build -t fastmcp-threatintel .

# Build documentation
uv run mkdocs build
```

## Development Standards

- ✅ Type hints for all functions
- 🧪 Tests for new features (>80% coverage)
- 📚 Documentation for public APIs
- 🎨 Code formatting with Ruff and Black
- 🔍 Linting with mypy and ruff
- 📦 Semantic versioning with Commitizen

## Contributing

We welcome contributions! Please see our [Contributing Guide](contributing.md) for details.

### Quick Contributing Steps
1. 🍴 Fork the repository
2. 🌿 Create a feature branch: `git checkout -b feature/amazing-feature`
3. 💻 Make your changes and add tests
4. ✅ Run tests: `uv run pytest`
5. 📝 Commit: `git commit -m 'Add amazing feature'`
6. 🚀 Push: `git push origin feature/amazing-feature`
7. 🔄 Create a Pull Request