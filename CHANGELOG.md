# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive cross-platform support (Windows, macOS, Linux)
- Docker containerization with multi-stage builds
- UV package manager support alongside Poetry
- Interactive CLI with Rich UI components
- Batch processing mode for bulk IOC analysis
- Advanced APT attribution with confidence scoring
- STIX-compliant threat intelligence output
- Interactive HTML reports with D3.js visualizations
- Comprehensive test suite with >80% coverage
- GitHub Actions CI/CD pipeline
- MkDocs documentation site
- Cross-platform installation scripts
- Progress indicators for long-running operations
- Enhanced error handling and retry mechanisms
- API rate limiting and caching improvements
- Enhanced geolocation support with IPinfo integration

### Changed
- Modernized project structure and dependencies
- Improved API error handling and resilience
- Enhanced logging and debugging capabilities
- Updated documentation with comprehensive examples
- Refactored core modules for better maintainability

### Fixed
- Windows path compatibility issues
- Poetry configuration errors
- Type hints and static analysis issues
- Cross-platform shell compatibility
- API timeout and retry logic

## [0.2.0] - 2024-12-22

### Added
- FastMCP integration for Claude Desktop and VSCode
- Multi-source threat intelligence (VirusTotal, OTX, AbuseIPDB)
- Basic IOC analysis functionality
- APT attribution capabilities
- Network graph visualization
- HTML report generation
- MCP server implementation
- Basic CLI interface

### Changed
- Initial project structure
- Core API integration modules
- Basic visualization components

### Fixed
- Initial bug fixes and stability improvements

## [0.1.0] - 2024-12-01

### Added
- Initial project setup
- Basic threat intelligence framework
- VirusTotal API integration
- Simple IOC analysis
- Basic reporting functionality

[Unreleased]: https://github.com/4R9UN/fastmcp-threatintel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/4R9UN/fastmcp-threatintel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/4R9UN/fastmcp-threatintel/releases/tag/v0.1.0