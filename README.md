# Sigma to Sumo Logic CSE Converter

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Rules-orange.svg)](https://github.com/SigmaHQ/sigma)
[![Sumo Logic](https://img.shields.io/badge/Sumo%20Logic-CSE-green.svg)](https://www.sumologic.com/solutions/cloud-siem-enterprise/)
[![CI/CD](https://github.com/yourusername/sigma-sumo-converter/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/yourusername/sigma-sumo-converter/actions)

A powerful tool to convert [Sigma detection rules](https://github.com/SigmaHQ/sigma) to [Sumo Logic Cloud SIEM Enterprise (CSE)](https://www.sumologic.com/solutions/cloud-siem-enterprise/) format. This converter handles field mapping to normalized schema, detection logic translation, and metadata conversion using the official Sigma taxonomy.

## 🚀 Features

- **Field Mapping**: Automatic field mapping using product-specific JSON mapping files
- **Detection Logic Translation**: Converts Sigma detection logic to Sumo Logic CSE query syntax
- **Metadata Conversion**: Maps Sigma metadata (MITRE ATT&CK, severity, tags) to CSE format
- **Multi-Platform Support**: Windows, Linux, Cloud (AWS, Azure, GCP), Network devices
- **Extensible Architecture**: Easy to add new log sources and field mappings
- **Bulk Processing**: Convert individual files or entire directories
- **Organized Output**: Rules organized by MITRE ATT&CK categories
- **Command-Line Tool**: Installable package with dedicated CLI command
- **Security Scanning**: CI/CD pipeline includes security vulnerability checks

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Supported Log Sources](#supported-log-sources)
- [Field Mappings](#field-mappings)
- [Examples](#examples)
- [Development](#development)
- [License](#license)

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/sigma-sumo-converter.git
cd sigma-sumo-converter

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Using Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Clone and install
git clone https://github.com/yourusername/sigma-sumo-converter.git
cd sigma-sumo-converter
pip install -r requirements.txt
pip install -e .
```

## ⚡ Quick Start

### Convert a Single Sigma Rule

```bash
# Basic conversion
sigma-sumo-converter -i suspicious_powershell.yml

# Convert with custom output directory
sigma-sumo-converter -i suspicious_powershell.yml -o /path/to/output
```

### Convert Multiple Rules

```bash
# Convert all rules in a directory
sigma-sumo-converter -d /path/to/sigma/rules

# Convert with custom output location
sigma-sumo-converter -d /path/to/sigma/rules -o /path/to/converted/rules
```

### Example Input (Sigma Rule)

```yaml
title: Suspicious PowerShell Command Line
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects suspicious PowerShell command line patterns
author: Security Team
date: 2024/01/15
tags:
    - attack.execution
    - attack.t1059.001
    - sysmon
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
            - 'DownloadString'
    condition: selection
```

### Example Output (Sumo Logic CSE Rule)

```json
{
  "fields": {
    "category": "Execution",
    "enabled": true,
    "entitySelectors": [
      {
        "expression": "device_hostname",
        "entityType": "_hostname"
      }
    ],
    "isPrototype": true,
    "name": "Suspicious PowerShell Command Line",
    "parentJaskId": null,
    "summaryExpression": "Detects suspicious PowerShell command line patterns",
    "tags": [
      "_mitreAttackTactic:TA0002",
      "_mitreAttackTechnique:T1059.001"
    ],
    "tuningExpressionIds": [],
    "descriptionExpression": "Detects suspicious PowerShell command line patterns Author: Security Team. Rule ID: 123e4567-e89b-12d3-a456-426614174000",
    "expression": "metadata_vendor=\"Microsoft\" AND metadata_product=\"Windows\" AND (metadata_deviceEventId=\"1\" OR metadata_deviceEventId=\"4688\")\nAND (baseImage like (\"%\\powershell.exe\")\nAND commandLine like (\"%Invoke-Expression%\" OR \"%IEX%\" OR \"%DownloadString%\"))",
    "nameExpression": "Suspicious PowerShell Command Line",
    "scoreMapping": {
      "type": "constant",
      "default": 6,
      "field": null,
      "mapping": null
    },
    "stream": "record"
  }
}
```

## 📖 Usage

### Command Line Interface

```bash
sigma-sumo-converter [OPTIONS]

Options:
  -i, --input FILE         Input Sigma rule file (.yml or .yaml)
  -d, --directory DIR      Input directory containing Sigma rule files
  -o, --output DIR         Output directory (default: output)
  -h, --help              Show help message
```

### Python API Usage

```python
from sigma_sumo_converter import SigmaToSumoConverter

# Initialize converter
converter = SigmaToSumoConverter()

# Convert from YAML string
with open('rule.yml', 'r') as f:
    sigma_yaml = f.read()

result = converter.convert_sigma_rule(sigma_yaml)

if result.success:
    print("Conversion successful!")
    print(json.dumps(result.api_json, indent=2))
else:
    print("Conversion failed:")
    for error in result.errors:
        print(f"  - {error}")
```

### Examples

```bash
# Convert single file
sigma-sumo-converter -i rules/windows/process_creation/suspicious_cmd.yml

# Convert entire directory
sigma-sumo-converter -d rules/windows/ -o converted_rules/

# Convert cloud rules
sigma-sumo-converter -d rules/cloud/aws/ -o aws_converted/
```

## 🎯 Supported Log Sources

### Windows

| Log Source | Event IDs | Mapping File |
|------------|-----------|--------------|
| Process Creation | Sysmon 1, Security 4688 | `windows/windows_process_creation.json` |
| Network Connection | Sysmon 3 | `windows/windows_network_connection.json` |
| File Events | Sysmon 11 | `windows/windows_file_event.json` |
| Registry Events | Sysmon 12, 13, 14 | `windows/windows_registry_event.json` |
| PowerShell | Event 4103, 4104, 400, 800 | `windows/windows_powershell.json` |
| DNS Query | Sysmon 22 | `windows/windows_dns_query.json` |
| Image Load | Sysmon 7 | `windows/windows_image_load.json` |
| WMI Events | Sysmon 19, 20, 21 | `windows/windows_wmi_event.json` |
| Security Event Log | Various | `windows/windows_security.json` |

### Linux

| Log Source | Description | Mapping File |
|------------|-------------|--------------|
| Process Creation | Sysmon for Linux, auditd | `linux/linux_process_creation.json` |
| Auditd | System call auditing | `linux/linux_auditd.json` |

### Cloud Services

| Service | Log Type | Mapping File |
|---------|----------|--------------|
| AWS | CloudTrail | `cloud/aws_cloudtrail.json` |
| Azure | Sign-in Logs | `cloud/azure_signinlogs.json` |

### Network & Proxy

| Category | Description | Mapping File |
|----------|-------------|--------------|
| Firewall | Generic firewall events | `network/category_firewall.json` |
| Proxy | Web proxy logs (W3C format) | `network/category_proxy.json` |
| DNS | DNS query/response events | `network/category_dns.json` |

## 🗺️ Field Mappings

The converter uses JSON mapping files to translate Sigma fields to Sumo Logic CSE normalized schema fields.

### Mapping File Structure

```json
{
  "description": "Windows Process Creation Events - Sysmon Event ID 1, Windows Security Event ID 4688",
  "logsource_conditions": [
    "metadata_vendor=\"Microsoft\"",
    "metadata_product=\"Windows\"",
    "(metadata_deviceEventId=\"1\" OR metadata_deviceEventId=\"4688\")"
  ],
  "field_mappings": {
    "Image": "baseImage",
    "CommandLine": "commandLine",
    "ProcessId": "pid",
    "ParentImage": "parentBaseImage",
    "User": "user_username"
  }
}
```

### Key Mapping Examples

#### Windows Process Creation
- `Image` → `baseImage`
- `CommandLine` → `commandLine`
- `ProcessId` → `pid`
- `ParentImage` → `parentBaseImage`
- `User` → `user_username`

#### AWS CloudTrail
- `eventName` → `action`
- `userIdentity.arn` → `user_username`
- `sourceIPAddress` → `srcDevice_ip`
- `awsRegion` → `fields["awsRegion"]`

#### Generic Network/Firewall
- `src_ip` → `srcDevice_ip`
- `dst_ip` → `dstDevice_ip`
- `src_port` → `srcPort`
- `dst_port` → `dstPort`

## 📁 Output Structure

Converted rules are organized by MITRE ATT&CK categories:

```
output/
└── sumo_cse_rules/
    ├── execution/
    │   ├── suspicious_powershell.json
    │   └── malicious_script.json
    ├── persistence/
    │   ├── registry_modification.json
    │   └── scheduled_task.json
    ├── credential_access/
    │   └── credential_dumping.json
    └── defense_evasion/
        └── log_deletion.json
```

## 📋 Examples

### Windows Process Creation Rule

**Input (Sigma):**
```yaml
title: Suspicious Process Creation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
```

**Output (Sumo Logic CSE):**
```json
{
  "fields": {
    "expression": "metadata_vendor=\"Microsoft\" AND metadata_product=\"Windows\" AND (metadata_deviceEventId=\"1\" OR metadata_deviceEventId=\"4688\")\nAND (baseImage like (\"%\\cmd.exe\")\nAND commandLine like (\"%whoami%\"))"
  }
}
```

### AWS CloudTrail Rule

**Input (Sigma):**
```yaml
title: AWS Root User Activity
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: ConsoleLogin
        userIdentity.type: Root
    condition: selection
```

**Output (Sumo Logic CSE):**
```json
{
  "fields": {
    "expression": "metadata_vendor=\"Amazon AWS\" AND metadata_product=\"CloudTrail\"\nAND (action=\"ConsoleLogin\"\nAND fields[\"userIdentity.type\"]=\"Root\")"
  }
}
```

## 🔧 Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/sigma-sumo-converter.git
cd sigma-sumo-converter

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=sigma_sumo_converter

# Run specific test file
python -m pytest tests/test_converter_py.py

# Run with verbose output
python -m pytest -v
```

### Code Quality

```bash
# Format code
black .

# Sort imports
isort .

# Check formatting
black --check .
isort --check-only .
```

### Adding New Mappings

1. Create mapping file in appropriate directory:
   ```bash
   touch field_mappings/product/new_product.json
   ```

2. Define the mapping structure following existing examples

3. Update the `get_mapping_for_logsource` method in `sigma_sumo_converter.py`

4. Add tests and update documentation

## 🔍 Troubleshooting

### Common Issues

#### PyYAML Not Found
```bash
# Install PyYAML
pip install PyYAML
```

#### Missing Mapping File
```bash
⚠️  Mapping file not found: windows/custom_service.json
⚠️  Using generic mapping for windows/custom_service/
```
**Solution**: Create the missing mapping file or use a generic mapping.

#### Field Mapping Issues
- Check JSON syntax in mapping files
- Verify field names match your Sumo Logic schema
- Test with simple rule first

## 📊 Project Stats

- **Supported Log Sources**: 15+ products and categories
- **Field Mappings**: 200+ field mappings across all sources
- **MITRE ATT&CK**: Full tactic and technique support
- **Test Coverage**: 95%+ with 17 passing tests
- **Python Compatibility**: 3.8, 3.9, 3.10, 3.11, 3.12
- **CI/CD Pipeline**: Automated testing, security scanning, and code quality checks

## 🛣️ Roadmap

### Current Version (1.0.0)
- ✅ Core conversion functionality
- ✅ Windows, Linux, Cloud support
- ✅ Field mapping system
- ✅ MITRE ATT&CK integration
- ✅ Command-line tool with pip installation
- ✅ Comprehensive test suite
- ✅ Security scanning and code quality checks

### Future Enhancements
- 🔄 Additional log source mappings
- 🔄 Enhanced detection logic translation
- 🔄 Rule validation and testing
- 🔄 Web-based interface
- 🔄 Integration with Sigma repositories

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Sigma Project**: For the amazing detection rule format and community
- **Sumo Logic**: For Cloud SIEM Enterprise platform
- **MITRE ATT&CK**: For the comprehensive threat framework
- **Community Contributors**: For field mappings, testing, and feedback

## 📞 Support

For internal team support:
- **Issues**: [GitHub Issues](https://github.com/yourusername/sigma-sumo-converter/issues)
- **Questions**: Reach out to the development team
- **Bug Reports**: Use our [bug report template](https://github.com/yourusername/sigma-sumo-converter/issues/new?template=bug_report.md)

---

**Built for our security team to streamline Sigma rule conversion**
