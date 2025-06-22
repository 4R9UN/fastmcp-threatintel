# 🛡️ FastMCP ThreatIntel - AI-Powered Threat Intelligence

[![CI/CD Pipeline](https://github.com/4R9UN/fastmcp-threatintel/actions/workflows/ci.yml/badge.svg)](https://github.com/4R9UN/fastmcp-threatintel/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/4R9UN/fastmcp-threatintel/branch/main/graph/badge.svg)](https://codecov.io/gh/4R9UN/fastmcp-threatintel)
[![PyPI version](https://badge.fury.io/py/fastmcp-threatintel.svg)](https://badge.fury.io/py/fastmcp-threatintel)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://hub.docker.com/r/arjuntrivedi/fastmcp-threatintel)

>🚀 **Modern, Cross-Platform Threat Intelligence Analysis Tool** powered by AI and multiple threat intelligence sources

A comprehensive Model Context Protocol (MCP) server that provides enterprise-grade threat intelligence capabilities through natural language AI prompts. Analyze IPs, domains, URLs, and file hashes across multiple threat intelligence platforms with advanced APT attribution and interactive reporting.

![Demo](src/Demo.gif)

## ✨ Key Features

### 🔍 **Multi-Source Intelligence**
- **VirusTotal**: File and URL reputation analysis
- **AlienVault OTX**: Open threat exchange data
- **AbuseIPDB**: IP reputation and geolocation
- **IPinfo**: Enhanced geolocation and ASN data

### 🤖 **AI-Powered Analysis**
- Natural language threat intelligence queries
- Advanced APT attribution with confidence scoring
- MITRE ATT&CK technique mapping
- Intelligent IOC type detection

### 📊 **Rich Reporting & Visualization**
- Interactive HTML reports with D3.js network graphs
- Multiple output formats (Markdown, JSON, HTML)
- STIX-compliant threat intelligence output
- Real-time progress indicators

### 🚀 **Multiple Deployment Options**
- **MCP Server**: Integrate with Claude Desktop and VSCode
- **Standalone CLI**: Interactive and batch processing modes
- **Docker Container**: Production-ready containerization
- **Python Package**: Embed in your applications

### 🌍 **Cross-Platform Support**
- Windows, macOS, and Linux compatibility
- Poetry and UV package manager support
- Docker multi-architecture builds
- Comprehensive CI/CD pipeline

## 🚀 Quick Start

### Using UV (Recommended)
```bash
# Clone and install
git clone https://github.com/4R9UN/fastmcp-threatintel.git
cd fastmcp-threatintel
uv sync

# Interactive setup wizard
uv run threatintel setup

# Analyze a single IOC
uv run threatintel analyze 192.168.1.1

# Start interactive mode
uv run threatintel interactive
```

### Using Poetry
```bash
# Clone and install
git clone https://github.com/4R9UN/fastmcp-threatintel.git
cd fastmcp-threatintel
poetry install

# Run analysis
poetry run threatintel analyze example.com --output-format html --open-browser
```

### Using Docker
```bash
# Pull and run
docker pull arjuntrivedi/fastmcp-threatintel:latest
docker run -e VIRUSTOTAL_API_KEY=your_key arjuntrivedi/fastmcp-threatintel analyze 8.8.8.8
```

### Using pip
```bash
pip install fastmcp-threatintel
threatintel setup  # Interactive configuration
threatintel analyze malware.exe --verbose
```

## 📋 Installation Options

=== "🔥 UV (Modern & Fast)"
    ```bash
    # Install UV if not already installed
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Clone and setup
    git clone https://github.com/4R9UN/fastmcp-threatintel.git
    cd fastmcp-threatintel
    uv sync
    
    # Quick test
    uv run threatintel --version
    ```

=== "📦 Poetry"
    ```bash
    # Install Poetry if not already installed
    curl -sSL https://install.python-poetry.org | python3 -
    
    # Clone and setup
    git clone https://github.com/4R9UN/fastmcp-threatintel.git
    cd fastmcp-threatintel
    poetry install
    
    # Activate environment
    poetry shell
    ```

=== "🐳 Docker"
    ```bash
    # Development mode with volume mount
    docker run -it --rm \
      -v $(pwd)/.env:/app/.env \
      -v $(pwd)/reports:/app/reports \
      arjuntrivedi/fastmcp-threatintel:latest
    
    # Production deployment
    docker-compose up -d
    ```

=== "🐍 pip"
    ```bash
    # Install from PyPI
    pip install fastmcp-threatintel
    
    # Or install development version
    pip install git+https://github.com/4R9UN/fastmcp-threatintel.git
    ```

## 🔧 Configuration

### Environment Variables
Create a `.env` file or set environment variables:

```bash
# Required APIs
VIRUSTOTAL_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_alienvault_otx_api_key

# Optional APIs
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
IPINFO_API_KEY=your_ipinfo_api_key

# Performance Settings
CACHE_TTL=3600              # Cache time-to-live in seconds
MAX_RETRIES=3               # Maximum API retry attempts
REQUEST_TIMEOUT=30          # Request timeout in seconds
```

### API Keys Setup

| Service | Required | Free Tier | Get Key |
|---------|----------|-----------|---------|
| **VirusTotal** | ✅ Yes | 1,000 requests/day | [Sign Up](https://www.virustotal.com/gui/join-us) |
| **OTX** | ✅ Yes | Unlimited | [Sign Up](https://otx.alienvault.com/) |
| **AbuseIPDB** | ❌ Optional | 1,000 requests/day | [Sign Up](https://www.abuseipdb.com/register) |
| **IPinfo** | ❌ Optional | 50,000 requests/month | [Sign Up](https://ipinfo.io/signup) |

## 💻 Usage Examples

### CLI Usage

```bash
# Analyze single IOC with rich output
threatintel analyze 192.168.1.1 --output-format table --verbose

# Batch analysis from file
threatintel batch iocs.txt --output-file report.html --output-format html

# Interactive mode with real-time analysis
threatintel interactive

# Server mode for MCP integration
threatintel server --host 0.0.0.0 --port 8000
```

### MCP Integration

#### Claude Desktop
Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "threatintel": {
      "command": "uv",
      "args": ["run", "src/threatintel/server.py"],
      "cwd": "/path/to/fastmcp-threatintel",
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key",
        "OTX_API_KEY": "your_key"
      }
    }
  }
}
```

#### VSCode with Cline
Configure in MCP settings:
```json
{
  "mcpServers": {
    "threatintel": {
      "command": "poetry",
      "args": ["run", "python", "src/threatintel/server.py"],
      "cwd": "C:\\path\\to\\fastmcp-threatintel"
    }
  }
}
```

### Python API

```python
import asyncio
from threatintel import analyze_iocs, IOC

async def analyze_threats():
    iocs = [
        {"value": "192.168.1.1", "type": "ip"},
        {"value": "malware.exe", "type": "md5"}
    ]
    
    report = await analyze_iocs(
        iocs=iocs,
        output_format="json",
        include_graph=True
    )
    
    print(report)

asyncio.run(analyze_threats())
```

## 🎯 AI Prompt Examples

### Basic Analysis
```
"Analyze IP 8.8.8.8 for any security threats and provide geolocation data"
"Check if domain example.com has any malicious associations"
"Investigate this hash: d41d8cd98f00b204e9800998ecf8427e"
```

### Advanced Attribution
```
"Perform comprehensive threat analysis on 185.220.101.1 including APT attribution with confidence scoring"
"Analyze these IOCs and identify potential nation-state actors: [list of IOCs]"
"Generate MITRE ATT&CK mapping for the identified threat patterns"
```

### Bulk Analysis
```
"Process this list of 100 IP addresses and generate an executive summary"
"Analyze all domains in our threat feed and identify high-confidence APT campaigns"
"Create a security incident report with timeline and attribution analysis"
```

## 📊 Reports & Visualization

### Interactive HTML Reports
- 🎨 Modern, responsive design with dark/light modes
- 📈 D3.js network graphs showing IOC relationships
- 🔍 Detailed tables with sortable columns
- 📋 APT attribution with confidence indicators
- 💾 Export capabilities (PDF, CSV, JSON)

### Output Formats
- **Table**: Rich terminal tables with color coding
- **Markdown**: GitHub-flavored markdown reports
- **JSON**: Structured data for automation
- **HTML**: Interactive web reports
- **STIX**: Industry-standard threat intelligence format

## 🏗️ Architecture

```mermaid
graph TB
    A[CLI Interface] --> B[Core Engine]
    C[MCP Server] --> B
    D[Python API] --> B
    
    B --> E[IOC Processor]
    B --> F[Attribution Engine]
    B --> G[Report Generator]
    
    E --> H[VirusTotal API]
    E --> I[OTX API]
    E --> J[AbuseIPDB API]
    E --> K[IPinfo API]
    
    F --> L[APT Patterns]
    F --> M[MITRE ATT&CK]
    
    G --> N[HTML Reports]
    G --> O[JSON Export]
    G --> P[STIX Output]
```

## 🧪 Development

### Setup Development Environment
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

### Testing
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

### Building
```bash
# Build package
uv build

# Build Docker image
docker build -t fastmcp-threatintel .

# Build documentation
uv run mkdocs build
```

## 📈 Performance & Scaling

### Benchmarks
- **Single IOC Analysis**: ~2-5 seconds
- **Batch Processing**: ~500 IOCs/minute
- **Memory Usage**: <100MB for typical workloads
- **Cache Hit Rate**: >90% in production environments

### Production Deployment
```yaml
# docker-compose.yml
version: '3.8'
services:
  threatintel:
    image: arjuntrivedi/fastmcp-threatintel:latest
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - OTX_API_KEY=${OTX_API_KEY}
      - CACHE_TTL=7200
      - MAX_RETRIES=5
    volumes:
      - ./reports:/app/reports
    ports:
      - "8000:8000"
    restart: unless-stopped
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/development/contributing.md) for details.

### Quick Contributing Steps
1. 🍴 Fork the repository
2. 🌿 Create a feature branch: `git checkout -b feature/amazing-feature`
3. 💻 Make your changes and add tests
4. ✅ Run tests: `uv run pytest`
5. 📝 Commit: `git commit -m 'Add amazing feature'`
6. 🚀 Push: `git push origin feature/amazing-feature`
7. 🔄 Create a Pull Request

### Development Standards
- ✅ Type hints for all functions
- 🧪 Tests for new features (>80% coverage)
- 📚 Documentation for public APIs
- 🎨 Code formatting with Ruff and Black
- 🔍 Linting with mypy and ruff
- 📦 Semantic versioning with Commitizen

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastMCP**: For the excellent MCP framework
- **VirusTotal**: For comprehensive malware analysis APIs
- **AlienVault OTX**: For open threat intelligence sharing
- **AbuseIPDB**: For IP reputation services
- **MITRE**: For the ATT&CK framework

## 🔗 Links

- 📚 [Documentation](https://4r9un.github.io/fastmcp-threatintel/)
- 🐛 [Issue Tracker](https://github.com/4R9UN/fastmcp-threatintel/issues)
- 💬 [Discussions](https://github.com/4R9UN/fastmcp-threatintel/discussions)
- 📦 [PyPI Package](https://pypi.org/project/fastmcp-threatintel/)
- 🐳 [Docker Hub](https://hub.docker.com/r/arjuntrivedi/fastmcp-threatintel)

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ for the cybersecurity community

[Report Bug](https://github.com/4R9UN/fastmcp-threatintel/issues) •
[Request Feature](https://github.com/4R9UN/fastmcp-threatintel/issues) •
[Documentation](https://4r9un.github.io/fastmcp-threatintel/)

</div>
