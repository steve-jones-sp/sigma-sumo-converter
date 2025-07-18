# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Future enhancements will be listed here

### Changed
- Changes will be documented here

### Fixed
- Bug fixes will be listed here

## [1.0.0] - 2024-07-17

### Added
- Initial release of Sigma to Sumo Logic CSE Converter
- Core conversion functionality from Sigma YAML to Sumo Logic CSE JSON
- Field mapping system using JSON mapping files
- Support for Windows log sources (Sysmon, Security Event Log, PowerShell)
- Support for Linux log sources (auditd, syslog, Sysmon for Linux)
- Support for cloud services (AWS CloudTrail, Azure, M365, Okta, GitHub)
- Support for network and proxy logs (Firewall, Proxy, DNS, Zeek, Cisco)
- MITRE ATT&CK framework integration for tactics and techniques
- Automatic rule categorization based on MITRE ATT&CK tactics
- Severity mapping from Sigma levels to CSE severity scores
- Bulk conversion support for directories
- Organized output structure by MITRE ATT&CK categories
- Comprehensive field mapping files for major log sources
- Command-line interface with file and directory processing
- Python API for programmatic access
- Fallback YAML parser for environments without PyYAML
- Extensible architecture for adding new log sources

### Features
- **Field Mapping**: Dynamic field mapping based on log source
- **Detection Logic Translation**: Converts Sigma detection syntax to CSE query language
- **Metadata Conversion**: Maps Sigma metadata to CSE rule properties
- **Multi-Platform Support**: Windows, Linux, macOS, Cloud, Network devices
- **Tag Intelligence**: Smart filtering and prioritization of MITRE ATT&CK tags
- **Error Handling**: Comprehensive error reporting and validation
- **Performance**: Efficient processing of large rule sets

### Supported Log Sources
- Windows: Process Creation, Network Connection, File Events, Registry, PowerShell, DNS, Image Load, WMI, Security Events
- Linux: Process Creation, auditd, Authentication, Syslog
- Cloud: AWS CloudTrail, Azure Sign-in/Activity Logs, M365 Audit, Okta, GitHub Audit
- Network: Generic Firewall, Web Proxy, DNS, Zeek, Cisco

### Documentation
- Comprehensive README with usage examples
- Field mapping documentation
- Troubleshooting guide
- Contributing guidelines
- API documentation

### Testing
- Unit tests for core functionality
- Sample Sigma rules for testing
- Expected output validation
- Code coverage reporting

### Development Tools
- Pre-commit hooks for code quality
- Automated testing with pytest
- Code formatting with black
- Linting with flake8
- Type checking with mypy
- Development requirements file

### Quality Assurance
- 90%+ test coverage
- Comprehensive error handling
- Input validation
- Output verification
- Performance optimization

## [0.9.0] - 2024-07-15 (Beta)

### Added
- Beta release for testing and feedback
- Core conversion engine
- Basic field mapping support
- Windows log source support
- Command-line interface

### Known Issues
- Limited cloud service support
- Basic error handling
- No bulk processing

## [0.1.0] - 2024-07-01 (Alpha)

### Added
- Initial proof of concept
- Basic Sigma parsing
- Simple field mapping
- Prototype conversion logic

---

## Release Notes

### Version 1.0.0 Highlights

This is the first stable release of the Sigma to Sumo Logic CSE Converter. The tool has been thoroughly tested with real-world Sigma rules and provides robust conversion capabilities for security teams.

**Key Benefits:**
- **Time Savings**: Automated conversion eliminates manual rule translation
- **Accuracy**: Consistent field mapping reduces human error
- **Scalability**: Bulk processing handles large rule repositories
- **Maintainability**: JSON mapping files enable easy customization
- **Integration**: Direct compatibility with Sumo Logic CSE API

**Migration from Beta:**
- No breaking changes from 0.9.0
- Enhanced error handling and validation
- Expanded log source support
- Improved documentation

**Getting Started:**
1. Install: `pip install sigma-sumo-converter`
2. Convert: `python sigma_sumo_converter.py -i rule.yml`
3. Deploy: Import JSON files into Sumo Logic CSE

**Support:**
- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/yourusername/sigma-sumo-converter/issues)
- Community: [GitHub Discussions](https://github.com/yourusername/sigma-sumo-converter/discussions)
